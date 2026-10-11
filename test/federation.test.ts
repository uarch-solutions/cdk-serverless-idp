import { createHash, randomBytes } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Browser, startDynamo, startIdp, type Harness } from './support/harness.js';

const CB = 'http://localhost:4999/callback';
let idp: Harness;
const upstream: { nonce?: string } = {};

beforeAll(async () => {
  startDynamo();
  idp = await startIdp('idp-federation');
  // Google's token endpoint answers with an ID token for the nonce our IdP sent.
  const realFetch = idp.deps.fetch;
  idp.deps.fetch = (async (url: string | URL, init?: RequestInit) => {
    if (String(url) === 'https://oauth2.googleapis.com/token') {
      const claims = { iss: 'https://accounts.google.com', aud: 'google-cid', exp: Math.floor(Date.now() / 1000) + 300, nonce: upstream.nonce, sub: 'google-123', email: 'ana@acme.test', email_verified: true, name: 'Ana G' };
      return new Response(JSON.stringify({ id_token: `e30.${Buffer.from(JSON.stringify(claims)).toString('base64url')}.sig` }), { headers: { 'content-type': 'application/json' } });
    }
    return realFetch(url, init);
  }) as typeof fetch;
  await idp.admin({ action: 'putRealm', realm: { id: 'acme', displayName: 'Acme', socialAutoLink: true, social: { google: { clientId: 'google-cid', clientSecret: 'gsecret', enabled: true } } } });
  await idp.admin({ action: 'putClient', client: { clientId: 'app', redirectUris: [CB], realms: ['acme'], firstParty: true } });
  await idp.admin({ action: 'upsertUser', realm: 'acme', user: { id: '11111111-1111-4111-8111-111111111111', email: 'ana@acme.test', name: 'Ana', emailVerified: true } });
}, 120_000);

afterAll(async () => idp?.close());

describe('social login (Google)', () => {
  it('links by verified e-mail when the realm allows it and signs in without a password', async () => {
    const b = new Browser();
    const verifier = randomBytes(32).toString('base64url');
    const challenge = createHash('sha256').update(verifier).digest('base64url');
    const login = await b.follow(`${idp.base}/realms/acme/auth?${new URLSearchParams({
      client_id: 'app', response_type: 'code', scope: 'openid email', redirect_uri: CB, code_challenge: challenge, code_challenge_method: 'S256',
    })}`, idp.base);
    const googleHref = /href="([^"]+\/federated\/google)"/.exec(login.html)![1]!;
    const toGoogle = await b.follow(`${idp.base}${googleHref}`, idp.base);
    const g = new URL(toGoogle.url);
    expect(g.origin).toBe('https://accounts.google.com');
    expect(g.searchParams.get('code_challenge_method')).toBe('S256');
    upstream.nonce = g.searchParams.get('nonce')!;
    const back = await b.follow(`${g.searchParams.get('redirect_uri')}?code=abc&state=${g.searchParams.get('state')}`, idp.base);
    expect(back.url.startsWith(CB)).toBe(true);
    expect((await idp.admin({ action: 'getUser', realm: 'acme', id: '11111111-1111-4111-8111-111111111111' })).identities).toEqual([{ provider: 'google', email: 'ana@acme.test' }]);
    // A replayed state is refused.
    const replay = await b.follow(`${g.searchParams.get('redirect_uri')}?code=abc&state=${g.searchParams.get('state')}`, idp.base);
    expect(replay.res.status).toBe(400);
  });

  it('unknown social account is not created (no self sign-up)', async () => {
    await idp.admin({ action: 'deleteUser', realm: 'acme', id: '11111111-1111-4111-8111-111111111111' });
    const b = new Browser();
    const login = await b.follow(`${idp.base}/realms/acme/auth?${new URLSearchParams({
      client_id: 'app', response_type: 'code', scope: 'openid', redirect_uri: CB, code_challenge: createHash('sha256').update('v'.repeat(43)).digest('base64url'), code_challenge_method: 'S256',
    })}`, idp.base);
    const toGoogle = await b.follow(`${idp.base}${/href="([^"]+\/federated\/google)"/.exec(login.html)![1]!}`, idp.base);
    const g = new URL(toGoogle.url);
    upstream.nonce = g.searchParams.get('nonce')!;
    const back = await b.follow(`${g.searchParams.get('redirect_uri')}?code=abc&state=${g.searchParams.get('state')}`, idp.base);
    expect(back.res.status).toBe(403);
  });
});
