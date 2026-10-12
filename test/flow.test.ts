import { createHash, randomBytes } from 'node:crypto';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { createLocalJWKSet, decodeJwt, jwtVerify } from 'jose';
import { ScanCommand } from '@aws-sdk/lib-dynamodb';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { base32Decode, hookSignature, hotp, totpStep } from '../runtime/crypto.js';
import { Browser, field, formAction, startDynamo, startIdp, type Harness } from './support/harness.js';

const APP_CB = 'http://localhost:4999/callback';
const PORTAL_HASH = '$argon2id$v=19$m=65536,p=4,t=3$2qYhB1lplxAraY2xzSIMTA$Qzzx8k64CotPJPBDL15pqDGBsyfY/x91Rhi96IZlnm8'; // node-argon2, "Senha-Antiga-123"
const MFA_SECRET = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';

let idp: Harness;
let hookServer: Server;
let hookUrl = '';
let clientSecret = '';
const hookCalls: { body: Record<string, any>; signatureOk: boolean }[] = []; // eslint-disable-line @typescript-eslint/no-explicit-any
let hookDecision: (b: Record<string, any>) => Record<string, unknown> = () => ({ allow: true, claims: { 'app:role': 'TEACHER', 'evil:role': 'ADMIN', sub: 'hijack' } }); // eslint-disable-line @typescript-eslint/no-explicit-any
const HOOK_SECRET = 'hook-secret-123';

const pkce = () => {
  const verifier = randomBytes(32).toString('base64url');
  return { verifier, challenge: createHash('sha256').update(verifier).digest('base64url') };
};
const authorizeUrl = (realm: string, challenge: string, extra: Record<string, string> = {}) =>
  `${idp.base}/realms/${realm}/auth?${new URLSearchParams({
    client_id: 'app', response_type: 'code', scope: 'openid email profile offline_access', redirect_uri: APP_CB, state: 'st-1',
    code_challenge: challenge, code_challenge_method: 'S256', prompt: 'consent', ...extra,
  })}`;
const basic = () => `Basic ${Buffer.from(`app:${clientSecret}`).toString('base64')}`;
const token = (realm: string, form: Record<string, string>) =>
  fetch(`${idp.base}/realms/${realm}/token`, { method: 'POST', headers: { authorization: basic(), 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(form) });

/** Runs the browser part: sign-in form, optional second factor; returns the redirect to the application. */
async function signIn(b: Browser, realm: string, email: string, password: string, opts: { totp?: () => string; extra?: Record<string, string> } = {}) {
  const { verifier, challenge } = pkce();
  let page = await b.follow(authorizeUrl(realm, challenge, opts.extra), idp.base);
  if (!page.html.includes('name="password"')) return { page, verifier };
  page = await b.post(`${idp.base}${formAction(page.html)}`, { _csrf: field(page.html, '_csrf'), email, password }, idp.base);
  if (opts.totp && page.html.includes('name="code"')) {
    page = await b.post(`${idp.base}${formAction(page.html)}`, { _csrf: field(page.html, '_csrf'), code: opts.totp() }, idp.base);
  }
  return { page, verifier };
}
const codeOf = (url: string) => new URL(url).searchParams.get('code');

beforeAll(async () => {
  startDynamo();
  idp = await startIdp('idp-flow');
  hookServer = createServer((req, res) => {
    let raw = '';
    req.on('data', (c) => { raw += c; });
    req.on('end', () => {
      const ts = String(req.headers['x-idp-timestamp']);
      const body = JSON.parse(raw);
      hookCalls.push({ body, signatureOk: req.headers['x-idp-signature'] === hookSignature(HOOK_SECRET, ts, raw) });
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify(hookDecision(body)));
    });
  });
  await new Promise<void>((r) => hookServer.listen(0, '127.0.0.1', r));
  hookUrl = `http://127.0.0.1:${(hookServer.address() as AddressInfo).port}/hook`;

  expect((await idp.admin({ action: 'putRealm', realm: { id: 'acme', displayName: 'Escola Acme', mfa: 'optional', branding: { color: '#0a7' } } })).ok).toBe(true);
  await idp.admin({ action: 'putRealm', realm: { id: 'other', displayName: 'Outra' } });
  const c = await idp.admin({
    action: 'putClient', client: { clientId: 'app', name: 'App', redirectUris: [APP_CB], realms: ['acme'], firstParty: true, claimPrefix: 'app', hook: { url: hookUrl, secret: HOOK_SECRET, onError: 'deny', timeoutMs: 2000 } },
  });
  clientSecret = c.clientSecret;
  await idp.admin({ action: 'importUsers', realm: 'acme', users: [
    { id: '11111111-1111-4111-8111-111111111111', email: 'Ana@Acme.test', name: 'Ana', status: 'ACTIVE', emailVerified: true, passwordHash: PORTAL_HASH },
    { id: '22222222-2222-4222-8222-222222222222', email: 'bia@acme.test', name: 'Bia', status: 'ACTIVE', emailVerified: true, passwordHash: PORTAL_HASH, mfaSecret: MFA_SECRET, mfaEnabledAt: new Date().toISOString(), recoveryHashes: [createHash('sha256').update('abcde-12345').digest('hex')] },
    { id: '33333333-3333-4333-8333-333333333333', email: 'caio@acme.test', name: 'Caio', status: 'DISABLED', emailVerified: true, passwordHash: PORTAL_HASH },
  ] });
}, 120_000);

afterAll(async () => {
  await idp?.close();
  hookServer?.close();
});

describe('OpenID Provider', () => {
  it('discovery and JWKS per realm, ES256 by default and RS256 (required by OpenID Connect), PKCE', async () => {
    const d = await (await fetch(`${idp.base}/realms/acme/.well-known/openid-configuration`)).json();
    expect(d.issuer).toBe(`${idp.base}/realms/acme`);
    expect(d.code_challenge_methods_supported).toEqual(['S256']);
    expect(d.id_token_signing_alg_values_supported).toEqual(['ES256', 'RS256']);
    expect(d.claims_parameter_supported).toBe(true);
    const jwks = await (await fetch(d.jwks_uri)).json();
    expect(jwks.keys[0]).toMatchObject({ kty: 'EC', crv: 'P-256', alg: 'ES256' });
    expect(jwks.keys[1]).toMatchObject({ kty: 'RSA', alg: 'RS256' });
    for (const k of jwks.keys) for (const p of ['d', 'p', 'q', 'dp', 'dq', 'qi']) expect(k[p]).toBeUndefined(); // public parts only
    expect((await fetch(`${idp.base}/realms/missing/.well-known/openid-configuration`)).status).toBe(404);
  });

  it('full sign-in with a migrated node-argon2 password: code + PKCE → JWT access token with the hook claims (prefix only)', async () => {
    const b = new Browser();
    const { page, verifier } = await signIn(b, 'acme', 'ana@acme.test', 'Senha-Antiga-123', { extra: { resource: 'urn:idp:app:app' } });
    expect(page.url.startsWith(APP_CB)).toBe(true);
    expect(new URL(page.url).searchParams.get('state')).toBe('st-1');
    const res = await token('acme', { grant_type: 'authorization_code', code: codeOf(page.url)!, redirect_uri: APP_CB, code_verifier: verifier, resource: 'urn:idp:app:app' });
    const t = await res.json();
    expect(res.status).toBe(200);
    const jwks = createLocalJWKSet(await (await fetch(`${idp.base}/realms/acme/jwks`)).json());
    const { payload } = await jwtVerify(t.access_token, jwks, { issuer: `${idp.base}/realms/acme`, audience: 'app' });
    expect(payload).toMatchObject({ sub: '11111111-1111-4111-8111-111111111111', realm: 'acme', 'app:role': 'TEACHER' });
    expect(payload['evil:role']).toBeUndefined();
    expect(decodeJwt(t.id_token)).toMatchObject({ email: 'ana@acme.test', name: 'Ana', aud: 'app' });
    expect(t.refresh_token).toBeTruthy();
    const login = hookCalls.find((h) => h.body.event === 'login')!;
    expect(login.signatureOk).toBe(true);
    expect(login.body).toMatchObject({ realm: 'acme', clientId: 'app', method: 'password', user: { email: 'ana@acme.test' } });

    // Refresh rotates; reusing the old refresh token revokes the whole family.
    const r1 = await (await token('acme', { grant_type: 'refresh_token', refresh_token: t.refresh_token })).json();
    expect(r1.access_token).toBeTruthy();
    // Without `resource`: a standard access token for the userinfo endpoint.
    const me = await fetch(`${idp.base}/realms/acme/me`, { headers: { authorization: `Bearer ${r1.access_token}` } });
    expect(me.status).toBe(200);
    expect(await me.json()).toMatchObject({ sub: '11111111-1111-4111-8111-111111111111', email: 'ana@acme.test' });
    expect(r1.refresh_token).not.toBe(t.refresh_token);
    const reuse = await token('acme', { grant_type: 'refresh_token', refresh_token: t.refresh_token });
    expect((await reuse.json()).error).toBe('invalid_grant');
    expect((await (await token('acme', { grant_type: 'refresh_token', refresh_token: r1.refresh_token })).json()).error).toBe('invalid_grant');
  });

  it('PKCE is mandatory and the code is bound to the verifier', async () => {
    const res = await fetch(`${idp.base}/realms/acme/auth?${new URLSearchParams({ client_id: 'app', response_type: 'code', scope: 'openid', redirect_uri: APP_CB })}`, { redirect: 'manual' });
    expect(new URL(res.headers.get('location')!).searchParams.get('error')).toBe('invalid_request');
    const b = new Browser();
    const { page } = await signIn(b, 'acme', 'ana@acme.test', 'Senha-Antiga-123');
    const bad = await token('acme', { grant_type: 'authorization_code', code: codeOf(page.url)!, redirect_uri: APP_CB, code_verifier: pkce().verifier });
    expect((await bad.json()).error).toBe('invalid_grant');
  });

  it('a confidential application may turn PKCE off (OpenID Basic profile); a public one never', async () => {
    const plain = await idp.admin({ action: 'putClient', client: { clientId: 'plain', redirectUris: [APP_CB], realms: ['acme'], firstParty: true, requirePkce: false } });
    expect(plain.client.requirePkce).toBe(false);
    const res = await fetch(`${idp.base}/realms/acme/auth?${new URLSearchParams({ client_id: 'plain', response_type: 'code', scope: 'openid', redirect_uri: APP_CB })}`, { redirect: 'manual' });
    expect(new URL(res.headers.get('location')!, idp.base).searchParams.get('error')).toBeNull();
    const pub = await idp.admin({ action: 'putClient', client: { clientId: 'spa', confidential: false, redirectUris: [APP_CB], realms: ['acme'], requirePkce: false } });
    expect(pub.client.requirePkce).toBe(true);
    const r2 = await fetch(`${idp.base}/realms/acme/auth?${new URLSearchParams({ client_id: 'spa', response_type: 'code', scope: 'openid', redirect_uri: APP_CB })}`, { redirect: 'manual' });
    expect(new URL(r2.headers.get('location')!).searchParams.get('error')).toBe('invalid_request');
  });

  it('wrong password, disabled person and unknown e-mail get the same answer; 10 failures lock the e-mail', async () => {
    for (const [email, pw] of [['ana@acme.test', 'errada-123'], ['caio@acme.test', 'Senha-Antiga-123'], ['ninguem@acme.test', 'x12345678']]) {
      const { page } = await signIn(new Browser(), 'acme', email!, pw!);
      expect(page.res.status).toBe(401);
      expect(page.html).toContain('E-mail ou senha incorretos.');
    }
    for (let i = 0; i < 10; i++) await signIn(new Browser(), 'acme', 'lock@acme.test', 'errada-123');
    const { page } = await signIn(new Browser(), 'acme', 'lock@acme.test', 'errada-123');
    expect(page.res.status).toBe(429);
  });

  it('second factor: TOTP migrated from the old system, replay refused, recovery code works once', async () => {
    const code = () => hotp(base32Decode(MFA_SECRET), totpStep(new Date()));
    const { page, verifier } = await signIn(new Browser(), 'acme', 'bia@acme.test', 'Senha-Antiga-123', { totp: code });
    expect(page.url.startsWith(APP_CB)).toBe(true);
    const t = await (await token('acme', { grant_type: 'authorization_code', code: codeOf(page.url)!, redirect_uri: APP_CB, code_verifier: verifier })).json();
    expect(decodeJwt(t.id_token).amr).toEqual(['pwd', 'otp']);
    // Same code again: refused (already used).
    const again = await signIn(new Browser(), 'acme', 'bia@acme.test', 'Senha-Antiga-123', { totp: code });
    expect(again.page.res.status).toBe(401);
    const rec = await signIn(new Browser(), 'acme', 'bia@acme.test', 'Senha-Antiga-123', { totp: () => 'ABCDE-12345' });
    expect(rec.page.url.startsWith(APP_CB)).toBe(true);
    const twice = await signIn(new Browser(), 'acme', 'bia@acme.test', 'Senha-Antiga-123', { totp: () => 'abcde-12345' });
    expect(twice.page.res.status).toBe(401);
  });

  it('the application hook can deny the sign-in (and a refresh)', async () => {
    hookDecision = (b) => (b.event === 'login' ? { allow: false, reason: 'Plano sem este módulo' } : { allow: true });
    const { page } = await signIn(new Browser(), 'acme', 'ana@acme.test', 'Senha-Antiga-123');
    const u = new URL(page.url);
    expect(u.searchParams.get('error')).toBe('access_denied');
    expect(u.searchParams.get('error_description')).toBe('Plano sem este módulo');
    hookDecision = () => ({ allow: true, claims: { 'app:role': 'TEACHER' } });
    const ok = await signIn(new Browser(), 'acme', 'ana@acme.test', 'Senha-Antiga-123');
    const t = await (await token('acme', { grant_type: 'authorization_code', code: codeOf(ok.page.url)!, redirect_uri: APP_CB, code_verifier: ok.verifier })).json();
    hookDecision = (b) => (b.event === 'token' ? { allow: false, reason: 'desativado no app' } : { allow: true });
    const refused = await (await token('acme', { grant_type: 'refresh_token', refresh_token: t.refresh_token })).json();
    expect(refused.error).toBe('invalid_grant');
    hookDecision = () => ({ allow: true, claims: { 'app:role': 'TEACHER' } });
  });

  it('a hook that does not answer denies by default', async () => {
    const saved = hookUrl;
    await idp.admin({ action: 'putClient', client: { clientId: 'app', hook: { url: 'http://127.0.0.1:1/down', onError: 'deny', timeoutMs: 300 } } });
    const { page } = await signIn(new Browser(), 'acme', 'ana@acme.test', 'Senha-Antiga-123');
    expect(new URL(page.url).searchParams.get('error')).toBe('access_denied');
    await idp.admin({ action: 'putClient', client: { clientId: 'app', hook: { url: saved, secret: HOOK_SECRET, onError: 'deny', timeoutMs: 2000 } } });
  });

  it('realms are isolated: the application is not allowed in another realm and a code does not cross realms', async () => {
    const { challenge } = pkce();
    const res = await fetch(authorizeUrl('other', challenge), { redirect: 'manual' });
    expect(res.status).toBe(400); // unknown client in this realm: error page, never a redirect
    const { page, verifier } = await signIn(new Browser(), 'acme', 'ana@acme.test', 'Senha-Antiga-123');
    const cross = await token('other', { grant_type: 'authorization_code', code: codeOf(page.url)!, redirect_uri: APP_CB, code_verifier: verifier });
    expect(cross.status).toBe(401); // the client does not exist there
  });

  it('forgot password: same answer for any e-mail, link by e-mail, new password works and the old one does not', async () => {
    const b = new Browser();
    let page = await b.follow(`${idp.base}/realms/acme/forgot`, idp.base);
    page = await b.post(`${idp.base}/realms/acme/forgot`, { _csrf: field(page.html, '_csrf'), email: 'ana@acme.test' }, idp.base);
    expect(page.html).toContain('Se o e-mail tiver acesso');
    const unknown = await b.post(`${idp.base}/realms/acme/forgot`, { _csrf: field(page.html, '_csrf') || b.jar.get('_csrf')!, email: 'ghost@acme.test' }, idp.base);
    expect(unknown.html).toContain('Se o e-mail tiver acesso');
    const mail = idp.mailer.sent.find((m) => m.to === 'ana@acme.test')!;
    const link = /(http\S+\/action\/[\w-]+)/.exec(mail.text)![1]!;
    let form = await b.follow(link, idp.base);
    expect(form.html).toContain('ana@acme.test');
    form = await b.post(link, { _csrf: field(form.html, '_csrf'), password: 'Nova-Senha-456', confirm: 'Nova-Senha-456' }, idp.base);
    expect(form.html).toContain('Senha salva');
    expect((await b.follow(link, idp.base)).res.status).toBe(410); // single use
    expect((await signIn(new Browser(), 'acme', 'ana@acme.test', 'Senha-Antiga-123')).page.res.status).toBe(401);
    expect((await signIn(new Browser(), 'acme', 'ana@acme.test', 'Nova-Senha-456')).page.url.startsWith(APP_CB)).toBe(true);
  });

  it('forms without the CSRF token are refused', async () => {
    const res = await fetch(`${idp.base}/realms/acme/forgot`, { method: 'POST', body: new URLSearchParams({ email: 'ana@acme.test' }), headers: { 'content-type': 'application/x-www-form-urlencoded' } });
    expect(res.status).toBe(403);
  });

  it('invite link from the admin API sets the first password', async () => {
    const created = await idp.admin({ action: 'upsertUser', realm: 'acme', user: { email: 'novo@acme.test', name: 'Novo' } });
    expect(created.created).toBe(true);
    expect((await idp.admin({ action: 'upsertUser', realm: 'acme', user: { email: 'NOVO@acme.test', name: 'Outro' } })).user.id).toBe(created.user.id);
    const inv = await idp.admin({ action: 'invite', realm: 'acme', id: created.user.id, send: false });
    const b = new Browser();
    const form = await b.follow(inv.url, idp.base);
    expect(form.html).toContain('Crie sua senha');
    await b.post(inv.url, { _csrf: field(form.html, '_csrf'), password: 'Primeira-123', confirm: 'Primeira-123' }, idp.base);
    expect((await signIn(new Browser(), 'acme', 'novo@acme.test', 'Primeira-123')).page.url.startsWith(APP_CB)).toBe(true);
    expect((await idp.admin({ action: 'getUser', realm: 'acme', id: created.user.id })).user).toMatchObject({ hasPassword: true, emailVerified: true });
  });

  it('admin: a pre-hashed password replaces the current one (and ends sessions); redirect URIs are added, never replaced', async () => {
    const u = await idp.admin({ action: 'upsertUser', realm: 'acme', user: { email: 'eva@acme.test', name: 'Eva', passwordHash: PORTAL_HASH } });
    expect((await signIn(new Browser(), 'acme', 'eva@acme.test', 'Senha-Antiga-123')).page.url.startsWith(APP_CB)).toBe(true);
    expect((await idp.admin({ action: 'upsertUser', realm: 'acme', user: { id: u.user.id, email: 'eva@acme.test', name: 'Eva', passwordHash: 'plain' } })).error).toBe('INVALID_HASH');
    const r = await idp.admin({ action: 'addRedirectUris', clientId: 'app', redirectUris: ['https://b.example/cb', APP_CB], postLogoutRedirectUris: ['https://b.example/'] });
    expect(r.redirectUris).toBe(2);
    expect((await idp.admin({ action: 'getClient', clientId: 'app' })).client.redirectUris).toEqual([APP_CB, 'https://b.example/cb']);
  });

  it('account console: change password and turn on the second factor with re-authentication', async () => {
    const b = new Browser();
    let page = await b.follow(`${idp.base}/realms/acme/account`, idp.base);
    page = await b.post(`${idp.base}/realms/acme/account/password`, { _csrf: field(page.html, '_csrf'), email: 'novo@acme.test', password: 'Primeira-123', newPassword: 'Segunda-123', confirm: 'Segunda-123' }, idp.base);
    expect(page.html).toContain('Pronto.');
    page = await b.post(`${idp.base}/realms/acme/account/mfa/enable`, { _csrf: b.jar.get('_csrf')!, email: 'novo@acme.test', password: 'Segunda-123' }, idp.base);
    const secret = /<code>([A-Z2-7]+)<\/code>/.exec(page.html)![1]!;
    page = await b.post(`${idp.base}${formAction(page.html)}`, { _csrf: b.jar.get('_csrf')!, code: hotp(base32Decode(secret), totpStep(new Date())) }, idp.base);
    expect(page.html).toContain('códigos de recuperação');
    expect((await idp.admin({ action: 'getUser', realm: 'acme', email: 'novo@acme.test' })).user.mfaEnabled).toBe(true);
  });

  it('realm that requires a second factor enrolls it during the sign-in', async () => {
    await idp.admin({ action: 'putRealm', realm: { id: 'acme', mfa: 'required' } });
    const u = await idp.admin({ action: 'upsertUser', realm: 'acme', user: { email: 'duda@acme.test', name: 'Duda' } });
    await idp.admin({ action: 'setPassword', realm: 'acme', id: u.user.id, password: 'Duda-12345' });
    const b = new Browser();
    const { challenge } = pkce();
    let page = await b.follow(authorizeUrl('acme', challenge), idp.base);
    page = await b.post(`${idp.base}${formAction(page.html)}`, { _csrf: field(page.html, '_csrf'), email: 'duda@acme.test', password: 'Duda-12345' }, idp.base);
    expect(page.html).toContain('Ative a verificação em duas etapas');
    const secret = /<code>([A-Z2-7]+)<\/code>/.exec(page.html)![1]!;
    page = await b.post(`${idp.base}${formAction(page.html)}`, { _csrf: b.jar.get('_csrf')!, code: hotp(base32Decode(secret), totpStep(new Date())) }, idp.base);
    expect(page.html).toContain('códigos de recuperação');
    page = await b.post(`${idp.base}${formAction(page.html)}`, { _csrf: b.jar.get('_csrf')! }, idp.base);
    expect(page.url.startsWith(APP_CB)).toBe(true);
    await idp.admin({ action: 'putRealm', realm: { id: 'acme', mfa: 'optional' } });
  });

  it('second factor required for one person (not the realm): enrollment at sign-in, postponable during the grace period', async () => {
    const until = new Date(Date.now() + 3 * 86400_000).toISOString();
    const u = await idp.admin({ action: 'upsertUser', realm: 'acme', user: { email: 'prof@acme.test', name: 'Prof', mfaRequired: true, mfaGraceUntil: until } });
    await idp.admin({ action: 'setPassword', realm: 'acme', id: u.user.id, password: 'Prof-12345' });
    const b = new Browser();
    const { challenge } = pkce();
    let page = await b.follow(authorizeUrl('acme', challenge), idp.base);
    page = await b.post(`${idp.base}${formAction(page.html)}`, { _csrf: field(page.html, '_csrf'), email: 'prof@acme.test', password: 'Prof-12345' }, idp.base);
    expect(page.html).toContain('Agora não');
    const skip = /<form method="post" action="([^"]+mfa-skip)"/.exec(page.html)![1]!;
    page = await b.post(`${idp.base}${skip}`, { _csrf: b.jar.get('_csrf')! }, idp.base);
    expect(page.url.startsWith(APP_CB)).toBe(true);
    // Grace over: no skip.
    await idp.admin({ action: 'upsertUser', realm: 'acme', user: { id: u.user.id, email: 'prof@acme.test', name: 'Prof', mfaGraceUntil: new Date(Date.now() - 1000).toISOString() } });
    const b2 = new Browser();
    page = await b2.follow(authorizeUrl('acme', pkce().challenge), idp.base);
    page = await b2.post(`${idp.base}${formAction(page.html)}`, { _csrf: field(page.html, '_csrf'), email: 'prof@acme.test', password: 'Prof-12345' }, idp.base);
    expect(page.html).toContain('Ative a verificação em duas etapas');
    expect(page.html).not.toContain('Agora não');
    expect((await b2.fetch(`${idp.base}${skip.replace(/interaction\/[^/]+/, 'interaction/x')}`, { method: 'POST' })).status).toBeGreaterThanOrEqual(400);
  });

  it('temporary password set by an administrator: a new one is chosen at the next sign-in', async () => {
    const u = await idp.admin({ action: 'upsertUser', realm: 'acme', user: { email: 'tmp@acme.test', name: 'Tmp' } });
    await idp.admin({ action: 'setPassword', realm: 'acme', id: u.user.id, password: 'Temp-12345', temporary: true });
    const b = new Browser();
    const { challenge, verifier } = pkce();
    let page = await b.follow(authorizeUrl('acme', challenge), idp.base);
    page = await b.post(`${idp.base}${formAction(page.html)}`, { _csrf: field(page.html, '_csrf'), email: 'tmp@acme.test', password: 'Temp-12345' }, idp.base);
    expect(page.html).toContain('Crie uma senha nova');
    const same = await b.post(`${idp.base}${formAction(page.html)}`, { _csrf: b.jar.get('_csrf')!, password: 'Temp-12345', confirm: 'Temp-12345' }, idp.base);
    expect(same.res.status).toBe(400); // must be different
    page = await b.post(`${idp.base}${formAction(page.html)}`, { _csrf: b.jar.get('_csrf')!, password: 'Definitiva-123', confirm: 'Definitiva-123' }, idp.base);
    expect(page.url.startsWith(APP_CB)).toBe(true);
    expect((await token('acme', { grant_type: 'authorization_code', code: codeOf(page.url)!, redirect_uri: APP_CB, code_verifier: verifier })).status).toBe(200);
    expect((await idp.admin({ action: 'getUser', realm: 'acme', id: u.user.id })).user.passwordChangeRequired).toBe(false);
    expect((await signIn(new Browser(), 'acme', 'tmp@acme.test', 'Definitiva-123')).page.url.startsWith(APP_CB)).toBe(true);
  });

  it('disabling a person ends the open sessions; audit trail records the events', async () => {
    const t = await (async () => {
      const { page, verifier } = await signIn(new Browser(), 'acme', 'ana@acme.test', 'Nova-Senha-456');
      return (await token('acme', { grant_type: 'authorization_code', code: codeOf(page.url)!, redirect_uri: APP_CB, code_verifier: verifier })).json();
    })();
    await idp.admin({ action: 'upsertUser', realm: 'acme', user: { id: '11111111-1111-4111-8111-111111111111', email: 'ana@acme.test', name: 'Ana', status: 'DISABLED' } });
    expect((await (await token('acme', { grant_type: 'refresh_token', refresh_token: t.refresh_token })).json()).error).toBe('invalid_grant');
    const events = (await idp.admin({ action: 'audit', realm: 'acme' })).events.map((e: { event: string }) => e.event);
    expect(events).toEqual(expect.arrayContaining(['LOGIN', 'LOGIN_FAILED', 'MFA_RECOVERY_CODE_USED', 'PASSWORD_RESET', 'USER_UPDATED', 'LOGIN_DENIED_BY_APP']));
  });

  it('a customer that leaves: its realm goes with everything in it, and its addresses leave the shared application', async () => {
    await idp.admin({ action: 'putRealm', realm: { id: 'leaving', displayName: 'Leaving' } });
    await idp.admin({ action: 'putClient', client: { clientId: 'app', realms: ['acme', 'leaving'] } });
    const u = await idp.admin({ action: 'upsertUser', realm: 'leaving', user: { email: 'bye@leaving.test', name: 'Bye' } });
    await idp.admin({ action: 'setPassword', realm: 'leaving', id: u.user.id, password: 'Leaving-123' });
    const { page } = await signIn(new Browser(), 'leaving', 'bye@leaving.test', 'Leaving-123');
    expect(page.url.startsWith(APP_CB)).toBe(true); // a session and a grant exist now
    expect((await idp.admin({ action: 'listRealms' })).realms).toEqual(expect.arrayContaining(['acme', 'leaving']));

    const r = await idp.admin({ action: 'deleteRealm', realm: 'leaving' });
    expect(r).toMatchObject({ ok: true, deleted: true, people: 1 });
    expect((await fetch(`${idp.base}/realms/leaving/.well-known/openid-configuration`)).status).toBe(404);
    expect(await idp.store.userByEmail('leaving', 'bye@leaving.test')).toBeNull();
    const left = await idp.store.doc.send(new ScanCommand({ TableName: idp.store.table, FilterExpression: 'contains(pk, :r) OR contains(gsi3pk, :r)', ExpressionAttributeValues: { ':r': 'leaving' } }));
    expect(left.Items).toEqual([]);
    expect((await idp.admin({ action: 'listRealms' })).realms).not.toContain('leaving');
    expect((await idp.admin({ action: 'deleteRealm', realm: 'leaving' })).error).toBe('REALM_NOT_FOUND');

    await idp.admin({ action: 'addRedirectUris', clientId: 'app', redirectUris: ['https://leaving.example/cb'], postLogoutRedirectUris: ['https://leaving.example/bye'] });
    await idp.admin({ action: 'removeRedirectUris', clientId: 'app', redirectUris: ['https://leaving.example/cb'], postLogoutRedirectUris: ['https://leaving.example/bye'] });
    const c = (await idp.admin({ action: 'getClient', clientId: 'app' })).client;
    expect(c.redirectUris).toContain(APP_CB);
    expect(c.redirectUris).not.toContain('https://leaving.example/cb');
    expect(c.postLogoutRedirectUris).not.toContain('https://leaving.example/bye');
  });

  it('security headers: strict CSP without scripts, no framing', async () => {
    const res = await fetch(`${idp.base}/realms/acme/forgot`);
    expect(res.headers.get('content-security-policy')).toContain("default-src 'none'");
    expect(res.headers.get('content-security-policy')).toContain("frame-ancestors 'none'");
    expect(await res.text()).not.toContain('<script');
  });
});
