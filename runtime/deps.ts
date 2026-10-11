import { GetSecretValueCommand, PutSecretValueCommand, SecretsManagerClient } from '@aws-sdk/client-secrets-manager';
import { ConfigCache } from './config-cache.js';
import { Cipher } from './crypto.js';
import { HookCaller } from './hooks.js';
import { Mailer, SesMailer } from './mail.js';
import { Store } from './store.js';

/** Installation secret (one Secrets Manager secret: one read per cold start). */
export interface RuntimeSecret {
  /** Private signing keys (ES256 JWKs). The first one signs; the others only verify (rotation). */
  jwks: { keys: Record<string, unknown>[] };
  /** Cookie signing keys (the first signs). */
  cookieKeys: string[];
  /** 32-byte base64 key for AES-256-GCM (TOTP secrets, client and upstream secrets). */
  dataKey: string;
  /** Header CloudFront adds to every request; requests without it are refused (no direct Function URL access). */
  originVerify?: string;
}

export interface Settings {
  tableName: string;
  secretId: string;
  /** Public base URL, e.g. https://id.example.com (realms live under /realms/<realm>). */
  issuerBase: string;
  mailFrom?: string;
  productName: string;
  auditRetentionDays: number;
  /** How often a warm Lambda checks whether realms or applications changed (they stay in memory otherwise; 0 = no cache). */
  configCheckMs: number;
}

export interface Deps {
  settings: Settings;
  secret: RuntimeSecret;
  store: Store;
  /** Realms and applications for the web function (memory + version check). */
  config: ConfigCache;
  cipher: Cipher;
  mailer: Mailer;
  hooks: HookCaller;
  fetch: typeof fetch;
  now: () => Date;
}

export const settingsFromEnv = (env = process.env): Settings => ({
  tableName: env.TABLE_NAME ?? '',
  secretId: env.SECRET_ID ?? '',
  issuerBase: (env.ISSUER_BASE ?? '').replace(/\/$/, ''),
  mailFrom: env.MAIL_FROM || undefined,
  productName: env.PRODUCT_NAME || 'Sign in',
  auditRetentionDays: Number(env.AUDIT_RETENTION_DAYS || 365),
  configCheckMs: Number(env.CONFIG_CHECK_MS || env.REALM_CACHE_MS || 30_000),
});

let cached: { at: number; value: RuntimeSecret } | undefined;
const sm = () => new SecretsManagerClient({});

export async function readSecret(secretId: string, maxAgeMs = 300_000): Promise<RuntimeSecret | null> {
  if (cached && Date.now() - cached.at < maxAgeMs) return cached.value;
  const r = await sm().send(new GetSecretValueCommand({ SecretId: secretId }));
  let value: Partial<RuntimeSecret>;
  try {
    value = JSON.parse(r.SecretString ?? '{}') as Partial<RuntimeSecret>;
  } catch {
    return null; // placeholder created by CloudFormation: not bootstrapped yet
  }
  if (!value.jwks?.keys?.length || !value.cookieKeys?.length || !value.dataKey) return null;
  cached = { at: Date.now(), value: value as RuntimeSecret };
  return cached.value;
}

export async function writeSecret(secretId: string, value: RuntimeSecret) {
  await sm().send(new PutSecretValueCommand({ SecretId: secretId, SecretString: JSON.stringify(value) }));
  cached = { at: Date.now(), value };
}

export async function depsFromEnv(): Promise<Deps> {
  const settings = settingsFromEnv();
  const secret = await readSecret(settings.secretId);
  if (!secret) throw new Error('installation secret not bootstrapped yet (run the admin "bootstrap" action)');
  const cipher = new Cipher(Buffer.from(secret.dataKey, 'base64'));
  // The CloudFront origin header comes from the deployment (dynamic reference), not from the runtime secret.
  if (process.env.ORIGIN_VERIFY) secret.originVerify = process.env.ORIGIN_VERIFY;
  const store = new Store(settings.tableName);
  return {
    settings, secret, cipher, store,
    config: new ConfigCache(store, settings.configCheckMs),
    mailer: new SesMailer(settings.mailFrom),
    hooks: new HookCaller(cipher, fetch),
    fetch,
    now: () => new Date(),
  };
}
