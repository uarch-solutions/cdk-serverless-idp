import { createHash } from 'node:crypto';
import { randomToken } from './crypto.js';

export type SocialProvider = 'google' | 'facebook';
export const SOCIAL_PROVIDERS: SocialProvider[] = ['google', 'facebook'];
export interface ExternalProfile { subject: string; email: string | null; emailVerified: boolean; name: string | null }
export interface UpstreamState { uid: string; provider: SocialProvider; verifier: string; nonce: string }

const GRAPH = 'https://graph.facebook.com/v19.0';

export function newUpstreamState(uid: string, provider: SocialProvider): { state: string; data: UpstreamState } {
  return { state: randomToken(24), data: { uid, provider, verifier: randomToken(48), nonce: randomToken(24) } };
}

export function authorizationUrl(provider: SocialProvider, o: { clientId: string; redirectUri: string; state: string; data: UpstreamState }) {
  if (provider === 'google') {
    const challenge = createHash('sha256').update(o.data.verifier).digest('base64url');
    return `https://accounts.google.com/o/oauth2/v2/auth?${new URLSearchParams({
      client_id: o.clientId, redirect_uri: o.redirectUri, response_type: 'code', scope: 'openid email profile', state: o.state,
      nonce: o.data.nonce, code_challenge: challenge, code_challenge_method: 'S256', prompt: 'select_account',
    })}`;
  }
  return `https://www.facebook.com/v19.0/dialog/oauth?${new URLSearchParams({
    client_id: o.clientId, redirect_uri: o.redirectUri, response_type: 'code', scope: 'email,public_profile', state: o.state,
  })}`;
}

const json = async (res: Response, what: string) => {
  const body = (await res.json().catch(() => ({}))) as Record<string, unknown>;
  if (!res.ok || body.error) throw new Error(`${what} failed (${res.status})`);
  return body;
};

/**
 * Claims of an ID token received straight from the token endpoint over TLS (OIDC Core 3.1.3.7 allows skipping the
 * signature check in this case); issuer, audience, expiry and nonce are checked.
 */
export function profileFromIdToken(idToken: string, o: { issuers: string[]; audience: string; nonce: string; now?: number }): ExternalProfile {
  const part = idToken.split('.')[1];
  if (!part) throw new Error('malformed id_token');
  const c = JSON.parse(Buffer.from(part, 'base64url').toString('utf8')) as Record<string, unknown>;
  const now = o.now ?? Math.floor(Date.now() / 1000);
  const aud = Array.isArray(c.aud) ? c.aud : [c.aud];
  if (!o.issuers.includes(String(c.iss))) throw new Error('id_token issuer mismatch');
  if (!aud.includes(o.audience)) throw new Error('id_token audience mismatch');
  if (typeof c.exp !== 'number' || c.exp < now - 60) throw new Error('id_token expired');
  if (c.nonce !== o.nonce) throw new Error('id_token nonce mismatch');
  if (typeof c.sub !== 'string' || !c.sub) throw new Error('id_token without subject');
  return {
    subject: c.sub,
    email: typeof c.email === 'string' ? c.email.toLowerCase() : null,
    emailVerified: c.email_verified === true || c.email_verified === 'true',
    name: typeof c.name === 'string' ? c.name : null,
  };
}

export async function exchange(fetchFn: typeof fetch, provider: SocialProvider, o: { code: string; clientId: string; clientSecret: string; redirectUri: string; data: UpstreamState }): Promise<ExternalProfile> {
  if (provider === 'google') {
    const body = await json(await fetchFn('https://oauth2.googleapis.com/token', {
      method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ code: o.code, client_id: o.clientId, client_secret: o.clientSecret, redirect_uri: o.redirectUri, grant_type: 'authorization_code', code_verifier: o.data.verifier }),
    }), 'Google token exchange');
    if (typeof body.id_token !== 'string') throw new Error('Google did not return an id_token');
    return profileFromIdToken(body.id_token, { issuers: ['https://accounts.google.com', 'accounts.google.com'], audience: o.clientId, nonce: o.data.nonce });
  }
  const token = await json(await fetchFn(`${GRAPH}/oauth/access_token?${new URLSearchParams({
    client_id: o.clientId, client_secret: o.clientSecret, redirect_uri: o.redirectUri, code: o.code,
  })}`), 'Facebook token exchange');
  if (typeof token.access_token !== 'string') throw new Error('Facebook did not return an access token');
  const me = await json(await fetchFn(`${GRAPH}/me?${new URLSearchParams({ fields: 'id,name,email', access_token: token.access_token })}`), 'Facebook profile');
  if (!me.id) throw new Error('Facebook did not return the user id');
  // Facebook does not guarantee the e-mail still belongs to the person: never link by it.
  return { subject: String(me.id), email: typeof me.email === 'string' ? me.email.toLowerCase() : null, emailVerified: false, name: typeof me.name === 'string' ? me.name : null };
}
