import { InvokeCommand, LambdaClient } from '@aws-sdk/client-lambda';
import { Cipher, hookSignature } from './crypto.js';
import type { ClientRecord } from './store.js';

export interface HookInput {
  /** `login`: end of the sign-in (may deny). `token`: every access token (fresh claims; may deny a refresh). */
  event: 'login' | 'token';
  realm: string;
  clientId: string;
  user: { sub: string; email: string; name: string; emailVerified: boolean };
  /** How the person authenticated (only on `login`). */
  method?: 'password' | 'google' | 'facebook';
}
export interface HookResult { allow: boolean; reason?: string; claims: Record<string, unknown> }

const MAX_CLAIMS_BYTES = 4096;
const RESERVED = new Set(['iss', 'sub', 'aud', 'exp', 'iat', 'nbf', 'jti', 'realm', 'scope', 'client_id', 'auth_time', 'acr', 'amr', 'sid', 'azp']);

/** Keeps only `<prefix>:*` claims, never the reserved ones; null when the result is too large. */
export function sanitizeClaims(prefix: string, claims: unknown): Record<string, unknown> | null {
  if (!claims || typeof claims !== 'object' || Array.isArray(claims)) return {};
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(claims)) {
    if (!k.startsWith(`${prefix}:`) || RESERVED.has(k)) continue;
    out[k] = v;
  }
  return Buffer.byteLength(JSON.stringify(out)) > MAX_CLAIMS_BYTES ? null : out;
}

/**
 * Post-login hook of each application: HTTPS POST signed with HMAC (`X-Idp-Signature: sha256=…` over
 * `<X-Idp-Timestamp>.<body>`) or a direct Lambda invocation. Short timeout; on failure the application's `onError`
 * policy decides (deny by default).
 */
export class HookCaller {
  private lambda?: LambdaClient;
  constructor(private readonly cipher: Cipher, private readonly fetchFn: typeof fetch) {}

  async call(client: ClientRecord, input: HookInput): Promise<HookResult> {
    const hook = client.hook;
    if (!hook || (!hook.url && !hook.lambdaArn)) return { allow: true, claims: {} };
    const failure = (reason: string): HookResult => (hook.onError === 'allow' ? { allow: true, claims: {} } : { allow: false, reason, claims: {} });
    try {
      const raw = await this.invoke(hook, input);
      const body = (raw && typeof raw === 'object' ? raw : {}) as { allow?: unknown; reason?: unknown; claims?: unknown };
      if (typeof body.allow !== 'boolean') return failure('invalid hook response');
      if (!body.allow) return { allow: false, reason: typeof body.reason === 'string' ? body.reason.slice(0, 300) : undefined, claims: {} };
      const claims = sanitizeClaims(client.claimPrefix, body.claims);
      return claims ? { allow: true, claims } : failure('hook claims too large');
    } catch (e) {
      console.warn(JSON.stringify({ hookError: client.clientId, message: (e as Error).message }));
      return failure('hook unavailable');
    }
  }

  private async invoke(hook: NonNullable<ClientRecord['hook']>, input: HookInput): Promise<unknown> {
    const body = JSON.stringify(input);
    if (hook.lambdaArn) {
      this.lambda ??= new LambdaClient({});
      const r = await this.lambda.send(new InvokeCommand({ FunctionName: hook.lambdaArn, Payload: Buffer.from(body) }), { abortSignal: AbortSignal.timeout(hook.timeoutMs) });
      if (r.FunctionError) throw new Error(`hook lambda error: ${r.FunctionError}`);
      return JSON.parse(Buffer.from(r.Payload ?? []).toString() || '{}');
    }
    const timestamp = String(Math.floor(Date.now() / 1000));
    const secret = hook.secretEnc ? this.cipher.decrypt(hook.secretEnc) : '';
    const res = await this.fetchFn(hook.url!, {
      method: 'POST', body, signal: AbortSignal.timeout(hook.timeoutMs),
      headers: { 'content-type': 'application/json', 'x-idp-timestamp': timestamp, 'x-idp-signature': hookSignature(secret, timestamp, body) },
    });
    if (!res.ok) throw new Error(`hook HTTP ${res.status}`);
    return res.json();
  }
}
