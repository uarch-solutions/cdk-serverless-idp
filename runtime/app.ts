import Router from '@koa/router';
import Koa from 'koa';
import { koaBody } from 'koa-body';
import type Provider from 'oidc-provider';
import {
  newRecoveryCode, newTotpSecret, otpauthUri, randomToken, recoveryHash, safeEqual, sha256, verifyTotp,
} from './crypto.js';
import type { Deps } from './deps.js';
import { authorizationUrl, exchange, newUpstreamState, SOCIAL_PROVIDERS, type SocialProvider, type UpstreamState } from './federation.js';
import { hashPassword, passwordProblem, verifyPassword, burnPasswordCheck } from './passwords.js';
import { buildProvider } from './provider.js';
import type { Realm, UserRecord } from './store.js';
import * as v from './views.js';

const LOGIN_WINDOW = 15 * 60;
const MAX_LOGIN_FAILURES = 10;
const MAX_IP_FAILURES = 100;
const MAX_MFA_FAILURES = 5;
const RESET_TTL = 3600;
type Ctx = Koa.ParameterizedContext<Koa.DefaultState, Koa.DefaultContext & { params: Record<string, string> }>;
type Body = Record<string, string | undefined>;
const body = (ctx: Ctx) => (ctx.request as unknown as { body?: Body }).body ?? {};
const parse = koaBody({ urlencoded: true, json: false, multipart: false, formLimit: '32kb' });

class HttpError extends Error { constructor(readonly status: number, message: string) { super(message); } }

/**
 * Web entry point: realm routing, the hosted pages (sign-in, second factor, consent, social login, password reset,
 * invite, account console) and, for everything else under `/realms/<realm>`, the realm's `oidc-provider`.
 */
export function createApp(deps: Deps) {
  const { store, settings } = deps;
  const app = new Koa();
  app.proxy = true;
  const providers = new Map<string, { provider: Provider; version: string }>();

  async function realmOf(id: string): Promise<Realm> {
    if (!/^[a-z0-9][a-z0-9-]{0,62}$/.test(id)) throw new HttpError(404, 'realm not found');
    const realm = await deps.config.realm(id);
    if (!realm || !realm.enabled) throw new HttpError(404, 'realm not found');
    return realm;
  }

  function providerFor(realm: Realm): Provider {
    const hit = providers.get(realm.id);
    if (hit && hit.version === realm.updatedAt) return hit.provider;
    const provider = buildProvider(realm, deps);
    providers.set(realm.id, { provider, version: realm.updatedAt });
    return provider;
  }

  const base = (realm: Realm) => `/realms/${realm.id}`;
  const render = (ctx: Ctx, realm: Realm | null, title: string, html: string, status = 200) => {
    ctx.status = status;
    ctx.type = 'html';
    ctx.body = v.page({ realm, locale: realm?.locale ?? 'pt-BR', title, body: html });
  };

  // ---- CSRF (double submit: an httpOnly SameSite=Strict cookie and the same value in every form)

  function csrf(ctx: Ctx): string {
    let value = ctx.cookies.get('_csrf');
    if (!value || !/^[\w-]{20,64}$/.test(value)) {
      value = randomToken(18);
      ctx.cookies.set('_csrf', value, { httpOnly: true, sameSite: 'strict', secure: ctx.secure, path: '/', overwrite: true });
    }
    return value;
  }
  function checkCsrf(ctx: Ctx) {
    const cookie = ctx.cookies.get('_csrf');
    const sent = body(ctx)._csrf;
    if (!cookie || !sent || !safeEqual(cookie, sent)) throw new HttpError(403, 'invalid form token');
  }

  // ---- rate limiting

  async function tooMany(keys: { key: string; max: number }[]) {
    for (const k of keys) if ((await store.count(k.key)) >= k.max) return true;
    return false;
  }
  async function fail(keys: string[]) { for (const k of keys) await store.increment(k, LOGIN_WINDOW); }

  // ---- security headers and origin check

  app.use(async (ctx, next) => {
    // No custom domain: the issuer is the distribution's own *.cloudfront.net name (set by the CloudFront function).
    if (!settings.issuerBase) {
      const host = ctx.get('x-forwarded-host');
      if (!/^[a-z0-9]+\.cloudfront\.net$/.test(host)) { ctx.status = 400; ctx.body = 'issuer not configured'; return; }
      settings.issuerBase = `https://${host}`;
      await store.putInstallation(settings.issuerBase); // the admin API builds invite links with it
    }
    const origin = deps.secret.originVerify;
    if (origin && ctx.path !== '/healthz' && ctx.get('x-origin-verify') !== origin) {
      ctx.status = 403;
      ctx.body = 'forbidden';
      return;
    }
    ctx.set('X-Content-Type-Options', 'nosniff');
    ctx.set('Referrer-Policy', 'no-referrer');
    ctx.set('Strict-Transport-Security', 'max-age=63072000; includeSubDomains');
    ctx.set('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' https: data:; form-action 'self' https:; frame-ancestors 'none'; base-uri 'none'");
    try {
      await next();
    } catch (e) {
      const status = e instanceof HttpError ? e.status : 500;
      if (status === 500) console.error(JSON.stringify({ error: (e as Error).message, stack: (e as Error).stack, path: ctx.path }));
      const id = /^\/realms\/([^/]+)/.exec(ctx.path)?.[1];
      const realm = id ? deps.config.peek(id) : null;
      const t = v.strings(realm?.locale ?? 'pt-BR');
      render(ctx as Ctx, realm, t.errorTitle, v.message({ title: t.errorTitle, text: status === 404 ? 'Not found' : t.errorTitle, error: true }), status);
    }
  });

  const router = new Router();
  router.get('/healthz', (ctx) => { ctx.body = { ok: true }; });

  // ---- sign-in interaction

  async function interaction(ctx: Ctx, provider: Provider) {
    try {
      return await provider.interactionDetails(ctx.req, ctx.res);
    } catch (e) {
      console.warn(JSON.stringify({ interactionNotFound: (e as Error).message, detail: (e as { error_description?: string }).error_description, path: ctx.path, cookies: (ctx.get('cookie') || '').split(';').map((c) => c.split('=')[0]!.trim()) }));
      return null;
    }
  }

  const socialLinks = (realm: Realm, uid: string) =>
    SOCIAL_PROVIDERS.filter((p) => realm.social[p]?.enabled).map((p) => ({ provider: p, url: `${base(realm)}/interaction/${uid}/federated/${p}` }));

  function loginPage(ctx: Ctx, realm: Realm, uid: string, extra: { email?: string; error?: string } = {}, status = 200) {
    const t = v.strings(realm.locale);
    render(ctx, realm, t.signIn, v.loginForm(t, {
      action: `${base(realm)}/interaction/${uid}/login`, csrf: csrf(ctx), forgotUrl: `${base(realm)}/forgot`, social: socialLinks(realm, uid), ...extra,
    }), status);
  }

  async function finishLogin(ctx: Ctx, realm: Realm, provider: Provider, details: Awaited<ReturnType<Provider['interactionDetails']>>, user: UserRecord, method: 'password' | 'google' | 'facebook', mfa: boolean) {
    const clientId = String(details.params.client_id ?? '');
    const client = await deps.config.client(clientId);
    const r = client
      ? await deps.hooks.call(client, { event: 'login', realm: realm.id, clientId, method, user: { sub: user.id, email: user.email, name: user.name, emailVerified: user.emailVerified } })
      : { allow: false, reason: 'unknown application', claims: {} };
    ctx.respond = false;
    if (!r.allow) {
      await store.audit(realm.id, 'LOGIN_DENIED_BY_APP', { userId: user.id, clientId, reason: r.reason ?? null, ip: ctx.ip }, settings.auditRetentionDays);
      await provider.interactionFinished(ctx.req, ctx.res, { error: 'access_denied', error_description: r.reason ?? v.strings(realm.locale).deniedByApp }, { mergeWithLastSubmission: false });
      return;
    }
    await store.audit(realm.id, 'LOGIN', { userId: user.id, clientId, method, mfa, ip: ctx.ip }, settings.auditRetentionDays);
    const amr = method === 'password' ? (mfa ? ['pwd', 'otp'] : ['pwd']) : (mfa ? ['fed', 'otp'] : ['fed']);
    await provider.interactionFinished(ctx.req, ctx.res, { login: { accountId: user.id, amr } }, { mergeWithLastSubmission: false });
  }

  /** After the first factor: second factor (or its mandatory enrollment) or the end of the sign-in. */
  async function afterFirstFactor(ctx: Ctx, realm: Realm, provider: Provider, details: Awaited<ReturnType<Provider['interactionDetails']>>, user: UserRecord, method: 'password' | 'google' | 'facebook') {
    const t = v.strings(realm.locale);
    if (method === 'password' && user.passwordChangeRequired) {
      await store.putStep(`pwd#${details.uid}`, { userId: user.id }, 900);
      return render(ctx, realm, t.changeRequiredTitle, v.setPasswordForm(t, {
        action: `${base(realm)}/interaction/${details.uid}/new-password`, csrf: csrf(ctx), invite: false, email: user.email, title: t.changeRequiredTitle, help: t.changeRequiredHelp,
      }));
    }
    if (user.mfa?.enabledAt) {
      await store.putStep(`mfa#${details.uid}`, { userId: user.id, method }, 600);
      return render(ctx, realm, t.mfaTitle, v.mfaForm(t, { action: `${base(realm)}/interaction/${details.uid}/mfa`, csrf: csrf(ctx) }));
    }
    if (realm.mfa === 'required' || user.mfaRequired) {
      const secret = newTotpSecret();
      const graceUntil = user.mfaGraceUntil && new Date(user.mfaGraceUntil) > deps.now() ? user.mfaGraceUntil : null;
      await store.putStep(`mfa#${details.uid}`, { userId: user.id, method, enrollSecret: secret, graceUntil }, 900);
      return render(ctx, realm, t.enrollTitle, v.enrollForm(t, {
        action: `${base(realm)}/interaction/${details.uid}/mfa`, csrf: csrf(ctx), secret, uri: otpauthUri(secret, user.email, realm.displayName),
        ...(graceUntil ? { skip: { action: `${base(realm)}/interaction/${details.uid}/mfa-skip`, until: graceUntil } } : {}),
      }));
    }
    return finishLogin(ctx, realm, provider, details, user, method, false);
  }

  router.get('/realms/:realm/interaction/:uid', async (ctx) => {
    const realm = await realmOf(ctx.params.realm);
    const provider = providerFor(realm);
    const t = v.strings(realm.locale);
    const details = await interaction(ctx, provider);
    if (!details || details.uid !== ctx.params.uid) return render(ctx, realm, t.errorTitle, v.message({ title: t.errorTitle, text: t.linkExpired, error: true }), 400);
    if (details.prompt.name === 'login') return loginPage(ctx, realm, details.uid, { email: typeof details.params.login_hint === 'string' ? details.params.login_hint : undefined });
    if (details.prompt.name === 'consent') {
      const app = await deps.config.client(String(details.params.client_id));
      if (app?.firstParty) return grantConsent(ctx, provider, details);
      const scopes = String(details.params.scope ?? 'openid').split(' ').filter(Boolean);
      return render(ctx, realm, t.consentTitle, v.consentForm(t, {
        action: `${base(realm)}/interaction/${details.uid}/consent`, abort: `${base(realm)}/interaction/${details.uid}/abort`, csrf: csrf(ctx), clientName: app?.name ?? String(details.params.client_id), scopes,
      }));
    }
    throw new HttpError(400, `unsupported prompt ${details.prompt.name}`);
  });

  async function grantConsent(ctx: Ctx, provider: Provider, details: Awaited<ReturnType<Provider['interactionDetails']>>) {
    const d = details.prompt.details as { missingOIDCScope?: string[]; missingOIDCClaims?: string[]; missingResourceScopes?: Record<string, string[]> };
    const grant = details.grantId
      ? (await provider.Grant.find(details.grantId))!
      : new provider.Grant({ accountId: details.session!.accountId, clientId: String(details.params.client_id) });
    if (d.missingOIDCScope) grant.addOIDCScope(d.missingOIDCScope.join(' '));
    if (d.missingOIDCClaims) grant.addOIDCClaims(d.missingOIDCClaims);
    for (const [indicator, scopes] of Object.entries(d.missingResourceScopes ?? {})) grant.addResourceScope(indicator, scopes.join(' '));
    const grantId = await grant.save();
    ctx.respond = false;
    await provider.interactionFinished(ctx.req, ctx.res, { consent: { grantId } }, { mergeWithLastSubmission: true });
  }

  router.post('/realms/:realm/interaction/:uid/consent', parse, async (ctx) => {
    const realm = await realmOf(ctx.params.realm);
    const provider = providerFor(realm);
    checkCsrf(ctx);
    const details = await interaction(ctx, provider);
    if (!details || details.uid !== ctx.params.uid || details.prompt.name !== 'consent') throw new HttpError(400, 'invalid interaction');
    await grantConsent(ctx, provider, details);
  });

  router.get('/realms/:realm/interaction/:uid/abort', async (ctx) => {
    const realm = await realmOf(ctx.params.realm);
    const provider = providerFor(realm);
    ctx.respond = false;
    await provider.interactionFinished(ctx.req, ctx.res, { error: 'access_denied', error_description: 'The person did not authorize the application' }, { mergeWithLastSubmission: false });
  });

  router.post('/realms/:realm/interaction/:uid/login', parse, async (ctx) => {
    const realm = await realmOf(ctx.params.realm);
    const provider = providerFor(realm);
    const t = v.strings(realm.locale);
    checkCsrf(ctx);
    const details = await interaction(ctx, provider);
    if (!details || details.uid !== ctx.params.uid || details.prompt.name !== 'login') throw new HttpError(400, 'invalid interaction');
    const email = String(body(ctx).email ?? '').trim().toLowerCase().slice(0, 254);
    const password = String(body(ctx).password ?? '');
    const keys = [`login#${realm.id}#${sha256(email)}`, `ip#${ctx.ip}`];
    if (await tooMany([{ key: keys[0]!, max: MAX_LOGIN_FAILURES }, { key: keys[1]!, max: MAX_IP_FAILURES }])) {
      await store.audit(realm.id, 'LOGIN_THROTTLED', { email: sha256(email), ip: ctx.ip }, settings.auditRetentionDays);
      return loginPage(ctx, realm, details.uid, { email, error: t.tooMany }, 429);
    }
    const user = email ? await store.userByEmail(realm.id, email) : null;
    const ok = user ? await verifyPassword(user.passwordHash, password) : (await burnPasswordCheck(password), false);
    if (!ok || !user || user.status !== 'ACTIVE') {
      await fail(keys);
      await store.audit(realm.id, 'LOGIN_FAILED', { userId: user?.id ?? null, ip: ctx.ip }, settings.auditRetentionDays);
      return loginPage(ctx, realm, details.uid, { email, error: t.invalidLogin }, 401);
    }
    await store.resetCount(keys[0]!);
    await afterFirstFactor(ctx, realm, provider, details, user, 'password');
  });

  router.post('/realms/:realm/interaction/:uid/mfa', parse, async (ctx) => {
    const realm = await realmOf(ctx.params.realm);
    const provider = providerFor(realm);
    const t = v.strings(realm.locale);
    checkCsrf(ctx);
    const details = await interaction(ctx, provider);
    if (!details || details.uid !== ctx.params.uid) throw new HttpError(400, 'invalid interaction');
    const step = await store.step<{ userId: string; method: 'password' | 'google' | 'facebook'; enrollSecret?: string; recovery?: string[] }>(`mfa#${details.uid}`);
    const user = step ? await store.user(realm.id, step.userId) : null;
    if (!step || !user || user.status !== 'ACTIVE') return loginPage(ctx, realm, details.uid, { error: t.linkExpired }, 400);
    // Recovery codes were shown after enrollment: continue the sign-in.
    if (step.recovery) {
      await store.deleteStep(`mfa#${details.uid}`);
      return finishLogin(ctx, realm, provider, details, user, step.method, true);
    }
    const key = `mfa#${realm.id}#${user.id}`;
    if (await tooMany([{ key, max: MAX_MFA_FAILURES }])) return render(ctx, realm, t.mfaTitle, v.mfaForm(t, { action: ctx.path, csrf: csrf(ctx), error: t.tooMany }), 429);
    const code = String(body(ctx).code ?? '').replace(/\s/g, '');
    const now = deps.now();
    if (step.enrollSecret) {
      const matched = verifyTotp(step.enrollSecret, code, now, null);
      if (matched === null) {
        await store.increment(key, LOGIN_WINDOW);
        return render(ctx, realm, t.enrollTitle, v.enrollForm(t, { action: ctx.path, csrf: csrf(ctx), secret: step.enrollSecret, uri: otpauthUri(step.enrollSecret, user.email, realm.displayName), error: t.invalidCode }), 401);
      }
      const codes = Array.from({ length: 10 }, newRecoveryCode);
      await store.putUser({ ...user, mfa: { secretEnc: deps.cipher.encrypt(step.enrollSecret), enabledAt: now.toISOString(), lastStep: matched }, recoveryHashes: codes.map(recoveryHash), updatedAt: now.toISOString() });
      await store.audit(realm.id, 'MFA_ENABLED', { userId: user.id, ip: ctx.ip }, settings.auditRetentionDays);
      await store.putStep(`mfa#${details.uid}`, { ...step, enrollSecret: undefined, recovery: ['shown'] }, 900);
      return render(ctx, realm, t.recoveryTitle, v.recoveryCodes(t, { codes, action: ctx.path, csrf: csrf(ctx) }));
    }
    const matched = user.mfa ? verifyTotp(deps.cipher.decrypt(user.mfa.secretEnc), code, now, user.mfa.lastStep) : null;
    const recovery = matched === null && user.recoveryHashes.includes(recoveryHash(code)) ? recoveryHash(code) : null;
    if (matched === null && !recovery) {
      await store.increment(key, LOGIN_WINDOW);
      await store.audit(realm.id, 'MFA_FAILED', { userId: user.id, ip: ctx.ip }, settings.auditRetentionDays);
      return render(ctx, realm, t.mfaTitle, v.mfaForm(t, { action: ctx.path, csrf: csrf(ctx), error: t.invalidCode }), 401);
    }
    await store.putUser({
      ...user, updatedAt: now.toISOString(),
      ...(matched !== null ? { mfa: { ...user.mfa!, lastStep: matched } } : { recoveryHashes: user.recoveryHashes.filter((h) => h !== recovery) }),
    });
    if (recovery) await store.audit(realm.id, 'MFA_RECOVERY_CODE_USED', { userId: user.id, ip: ctx.ip }, settings.auditRetentionDays);
    await store.resetCount(key);
    await store.deleteStep(`mfa#${details.uid}`);
    await finishLogin(ctx, realm, provider, details, user, step.method, true);
  });

  router.post('/realms/:realm/interaction/:uid/new-password', parse, async (ctx) => {
    const realm = await realmOf(ctx.params.realm);
    const provider = providerFor(realm);
    const t = v.strings(realm.locale);
    checkCsrf(ctx);
    const details = await interaction(ctx, provider);
    if (!details || details.uid !== ctx.params.uid) throw new HttpError(400, 'invalid interaction');
    const step = await store.step<{ userId: string }>(`pwd#${details.uid}`);
    const user = step ? await store.user(realm.id, step.userId) : null;
    if (!step || !user || user.status !== 'ACTIVE' || !user.passwordChangeRequired) return loginPage(ctx, realm, details.uid, { error: t.linkExpired }, 400);
    const { password = '', confirm = '' } = body(ctx);
    const error = passwordProblem(password) ? t.tooShort : password !== confirm ? t.mismatch : (await verifyPassword(user.passwordHash, password)) ? t.mismatch : null;
    if (error) {
      return render(ctx, realm, t.changeRequiredTitle, v.setPasswordForm(t, { action: ctx.path, csrf: csrf(ctx), invite: false, email: user.email, title: t.changeRequiredTitle, help: t.changeRequiredHelp, error }), 400);
    }
    const updated: UserRecord = { ...user, passwordHash: await hashPassword(password), passwordChangeRequired: false, updatedAt: deps.now().toISOString() };
    await store.putUser(updated);
    await store.deleteStep(`pwd#${details.uid}`);
    await store.deleteByIndex('gsi3', `ACCOUNT#${realm.id}#${user.id}`);
    await store.audit(realm.id, 'PASSWORD_CHANGED', { userId: user.id, ip: ctx.ip, reason: 'temporary' }, settings.auditRetentionDays);
    await afterFirstFactor(ctx, realm, provider, details, updated, 'password');
  });

  router.post('/realms/:realm/interaction/:uid/mfa-skip', parse, async (ctx) => {
    const realm = await realmOf(ctx.params.realm);
    const provider = providerFor(realm);
    checkCsrf(ctx);
    const details = await interaction(ctx, provider);
    if (!details || details.uid !== ctx.params.uid) throw new HttpError(400, 'invalid interaction');
    const step = await store.step<{ userId: string; method: 'password' | 'google' | 'facebook'; enrollSecret?: string; graceUntil?: string | null }>(`mfa#${details.uid}`);
    const user = step ? await store.user(realm.id, step.userId) : null;
    // Skipping is only possible during the grace period of a person-level requirement.
    if (!step?.enrollSecret || !step.graceUntil || new Date(step.graceUntil) <= deps.now() || !user || user.status !== 'ACTIVE' || realm.mfa === 'required') {
      throw new HttpError(400, 'cannot skip');
    }
    await store.deleteStep(`mfa#${details.uid}`);
    await store.audit(realm.id, 'MFA_ENROLLMENT_POSTPONED', { userId: user.id, until: step.graceUntil, ip: ctx.ip }, settings.auditRetentionDays);
    await finishLogin(ctx, realm, provider, details, user, step.method, false);
  });

  // ---- social login (upstream OIDC/OAuth2)

  // One callback URL for every realm (Google and Facebook require each redirect URI to be registered): the realm
  // travels in the server-side state.
  const callbackUrl = (p: SocialProvider) => `${settings.issuerBase}/federated/callback/${p}`;

  router.get('/realms/:realm/interaction/:uid/federated/:provider', async (ctx) => {
    const realm = await realmOf(ctx.params.realm);
    const provider = providerFor(realm);
    const p = ctx.params.provider as SocialProvider;
    const conf = realm.social[p];
    if (!SOCIAL_PROVIDERS.includes(p) || !conf?.enabled) throw new HttpError(404, 'provider not enabled');
    const details = await interaction(ctx, provider);
    if (!details || details.uid !== ctx.params.uid) throw new HttpError(400, 'invalid interaction');
    const { state, data } = newUpstreamState(details.uid, realm.id, p);
    await store.putStep(`fed#${state}`, data, 600);
    ctx.redirect(authorizationUrl(p, { clientId: conf.clientId, redirectUri: callbackUrl(p), state, data }));
  });

  router.get('/federated/callback/:provider', async (ctx) => {
    const p = ctx.params.provider as SocialProvider;
    const state = String(ctx.query.state ?? '');
    const data = state && /^[\w-]{20,64}$/.test(state) ? await store.step<UpstreamState>(`fed#${state}`) : null;
    if (!data || data.provider !== p) return render(ctx, null, v.strings('pt-BR').errorTitle, v.message({ title: v.strings('pt-BR').errorTitle, text: v.strings('pt-BR').linkExpired, error: true }), 400);
    const realm = await realmOf(data.realm);
    const t = v.strings(realm.locale);
    const conf = realm.social[p];
    if (!conf?.enabled) return render(ctx, realm, t.errorTitle, v.message({ title: t.errorTitle, text: t.linkExpired, error: true }), 400);
    await store.deleteStep(`fed#${state}`);
    if (ctx.query.error || !ctx.query.code) return ctx.redirect(`${base(realm)}/interaction/${data.uid}`);
    const profile = await exchange(deps.fetch, p, { code: String(ctx.query.code), clientId: conf.clientId, clientSecret: deps.cipher.decrypt(conf.clientSecretEnc), redirectUri: callbackUrl(p), data });
    let identity = await store.identity(realm.id, p, profile.subject);
    if (!identity && realm.socialAutoLink && profile.email && profile.emailVerified) {
      const byEmail = await store.userByEmail(realm.id, profile.email);
      if (byEmail && byEmail.status === 'ACTIVE') {
        identity = { realm: realm.id, userId: byEmail.id, provider: p, subject: profile.subject, email: profile.email, createdAt: deps.now().toISOString() };
        await store.putIdentity(identity);
        await store.audit(realm.id, 'IDENTITY_LINKED', { userId: byEmail.id, provider: p }, settings.auditRetentionDays);
      }
    }
    if (!identity) {
      await store.audit(realm.id, 'LOGIN_FAILED', { provider: p, reason: 'no linked account', ip: ctx.ip }, settings.auditRetentionDays);
      return render(ctx, realm, t.errorTitle, v.message({ title: t.errorTitle, text: t.noAccount, error: true, link: { href: `${base(realm)}/interaction/${data.uid}`, label: t.signIn } }), 403);
    }
    await store.putStep(`fedok#${data.uid}`, { userId: identity.userId, method: p }, 300);
    ctx.redirect(`${base(realm)}/interaction/${data.uid}/federated-done`);
  });

  router.get('/realms/:realm/interaction/:uid/federated-done', async (ctx) => {
    const realm = await realmOf(ctx.params.realm);
    const provider = providerFor(realm);
    const details = await interaction(ctx, provider);
    if (!details || details.uid !== ctx.params.uid) throw new HttpError(400, 'invalid interaction');
    const step = await store.step<{ userId: string; method: SocialProvider }>(`fedok#${details.uid}`);
    const user = step ? await store.user(realm.id, step.userId) : null;
    await store.deleteStep(`fedok#${details.uid}`);
    if (!step || !user || user.status !== 'ACTIVE') return loginPage(ctx, realm, details.uid, { error: v.strings(realm.locale).noAccount }, 403);
    await afterFirstFactor(ctx, realm, provider, details, user, step.method);
  });

  // ---- forgot password, invite and reset links

  router.get('/realms/:realm/forgot', async (ctx) => {
    const realm = await realmOf(ctx.params.realm);
    const t = v.strings(realm.locale);
    render(ctx, realm, t.forgotTitle, v.forgotForm(t, { action: ctx.path, csrf: csrf(ctx) }));
  });

  router.post('/realms/:realm/forgot', parse, async (ctx) => {
    const realm = await realmOf(ctx.params.realm);
    const t = v.strings(realm.locale);
    checkCsrf(ctx);
    const email = String(body(ctx).email ?? '').trim().toLowerCase().slice(0, 254);
    const keys = [`forgot#${realm.id}#${sha256(email)}`, `forgotip#${ctx.ip}`];
    // Same answer whether the e-mail exists or not; quietly limited.
    if (email && !(await tooMany([{ key: keys[0]!, max: 5 }, { key: keys[1]!, max: 30 }]))) {
      await fail(keys);
      const user = await store.userByEmail(realm.id, email);
      if (user && user.status === 'ACTIVE') {
        const token = randomToken(32);
        await store.putActionToken(sha256(token), { realm: realm.id, userId: user.id, kind: 'reset', returnTo: realm.homeUrl ?? null }, RESET_TTL);
        await deps.mailer.send({
          to: user.email, subject: `${t.resetTitle} — ${realm.displayName}`,
          text: `${t.resetTitle}: ${settings.issuerBase}${base(realm)}/action/${token}\n\n${t.forgotSent}`,
        });
        await store.audit(realm.id, 'PASSWORD_RESET_REQUESTED', { userId: user.id, ip: ctx.ip }, settings.auditRetentionDays);
      }
    }
    render(ctx, realm, t.forgotTitle, v.forgotForm(t, { action: ctx.path, csrf: csrf(ctx), sent: true }));
  });

  async function actionTarget(realm: Realm, token: string) {
    const record = /^[\w-]{20,100}$/.test(token) ? await store.actionToken(sha256(token)) : null;
    if (!record || record.realm !== realm.id) return null;
    const user = await store.user(realm.id, record.userId);
    return user ? { record, user } : null;
  }

  router.get('/realms/:realm/action/:token', async (ctx) => {
    const realm = await realmOf(ctx.params.realm);
    const t = v.strings(realm.locale);
    const target = await actionTarget(realm, ctx.params.token);
    if (!target) return render(ctx, realm, t.errorTitle, v.message({ title: t.errorTitle, text: t.linkExpired, error: true, link: { href: `${base(realm)}/forgot`, label: t.forgot } }), 410);
    render(ctx, realm, t.setPassword, v.setPasswordForm(t, { action: ctx.path, csrf: csrf(ctx), invite: target.record.kind === 'invite', email: target.user.email }));
  });

  router.post('/realms/:realm/action/:token', parse, async (ctx) => {
    const realm = await realmOf(ctx.params.realm);
    const t = v.strings(realm.locale);
    checkCsrf(ctx);
    const target = await actionTarget(realm, ctx.params.token);
    if (!target) return render(ctx, realm, t.errorTitle, v.message({ title: t.errorTitle, text: t.linkExpired, error: true }), 410);
    const { password = '', confirm = '' } = body(ctx);
    const problem = passwordProblem(password);
    const error = problem ? t.tooShort : password !== confirm ? t.mismatch : null;
    if (error) return render(ctx, realm, t.setPassword, v.setPasswordForm(t, { action: ctx.path, csrf: csrf(ctx), invite: target.record.kind === 'invite', email: target.user.email, error }), 400);
    const now = deps.now().toISOString();
    await store.putUser({ ...target.user, passwordHash: await hashPassword(password), emailVerified: true, passwordChangeRequired: false, updatedAt: now });
    await store.deleteActionToken(sha256(ctx.params.token));
    // A new password ends every open session of the person.
    await store.deleteByIndex('gsi3', `ACCOUNT#${realm.id}#${target.user.id}`);
    await store.audit(realm.id, target.record.kind === 'invite' ? 'INVITE_ACCEPTED' : 'PASSWORD_RESET', { userId: target.user.id, ip: ctx.ip }, settings.auditRetentionDays);
    const back = target.record.returnTo ?? realm.homeUrl;
    render(ctx, realm, t.setPassword, v.message({ title: t.done, text: t.passwordSaved, ...(back ? { link: { href: back, label: t.backToApp } } : {}) }));
  });

  // ---- account console (stateless: every change re-checks the current password)

  async function reauth(ctx: Ctx, realm: Realm): Promise<UserRecord | string> {
    const t = v.strings(realm.locale);
    checkCsrf(ctx);
    const email = String(body(ctx).email ?? '').trim().toLowerCase().slice(0, 254);
    const keys = [`login#${realm.id}#${sha256(email)}`, `ip#${ctx.ip}`];
    if (await tooMany([{ key: keys[0]!, max: MAX_LOGIN_FAILURES }, { key: keys[1]!, max: MAX_IP_FAILURES }])) return t.tooMany;
    const user = email ? await store.userByEmail(realm.id, email) : null;
    const ok = user ? await verifyPassword(user.passwordHash, String(body(ctx).password ?? '')) : (await burnPasswordCheck(String(body(ctx).password ?? '')), false);
    if (!ok || !user || user.status !== 'ACTIVE') {
      await fail(keys);
      return t.invalidLogin;
    }
    await store.resetCount(keys[0]!);
    return user;
  }

  const accountView = (ctx: Ctx, realm: Realm, o: { notice?: string; error?: string; email?: string } = {}, status = 200) => {
    const t = v.strings(realm.locale);
    render(ctx, realm, t.accountTitle, v.accountPage(t, { base: `${base(realm)}/account`, csrf: csrf(ctx), mfaRequired: realm.mfa === 'required', ...o }), status);
  };

  router.get('/realms/:realm/account', async (ctx) => accountView(ctx, await realmOf(ctx.params.realm)));

  router.post('/realms/:realm/account/password', parse, async (ctx) => {
    const realm = await realmOf(ctx.params.realm);
    const t = v.strings(realm.locale);
    const user = await reauth(ctx, realm);
    if (typeof user === 'string') return accountView(ctx, realm, { error: user }, 401);
    const { newPassword = '', confirm = '' } = body(ctx);
    const error = passwordProblem(newPassword) ? t.tooShort : newPassword !== confirm ? t.mismatch : null;
    if (error) return accountView(ctx, realm, { error, email: user.email }, 400);
    await store.putUser({ ...user, passwordHash: await hashPassword(newPassword), passwordChangeRequired: false, updatedAt: deps.now().toISOString() });
    await store.deleteByIndex('gsi3', `ACCOUNT#${realm.id}#${user.id}`);
    await store.audit(realm.id, 'PASSWORD_CHANGED', { userId: user.id, ip: ctx.ip }, settings.auditRetentionDays);
    accountView(ctx, realm, { notice: t.done, email: user.email });
  });

  router.post('/realms/:realm/account/mfa/enable', parse, async (ctx) => {
    const realm = await realmOf(ctx.params.realm);
    const t = v.strings(realm.locale);
    const user = await reauth(ctx, realm);
    if (typeof user === 'string') return accountView(ctx, realm, { error: user }, 401);
    if (user.mfa?.enabledAt) return accountView(ctx, realm, { notice: t.mfaOn, email: user.email });
    const secret = newTotpSecret();
    const stepKey = randomToken(18);
    await store.putStep(`acct#${stepKey}`, { userId: user.id, secret }, 900);
    render(ctx, realm, t.enrollTitle, v.enrollForm(t, {
      action: `${base(realm)}/account/mfa/confirm/${stepKey}`, csrf: csrf(ctx), secret, uri: otpauthUri(secret, user.email, realm.displayName), help: t.enrollHelp.split('. ').slice(1).join('. '),
    }));
  });

  router.post('/realms/:realm/account/mfa/confirm/:key', parse, async (ctx) => {
    const realm = await realmOf(ctx.params.realm);
    const t = v.strings(realm.locale);
    checkCsrf(ctx);
    const step = await store.step<{ userId: string; secret: string }>(`acct#${ctx.params.key}`);
    const user = step ? await store.user(realm.id, step.userId) : null;
    if (!step || !user) return accountView(ctx, realm, { error: t.linkExpired }, 400);
    const key = `mfa#${realm.id}#${user.id}`;
    if (await tooMany([{ key, max: MAX_MFA_FAILURES }])) return accountView(ctx, realm, { error: t.tooMany }, 429);
    const now = deps.now();
    const matched = verifyTotp(step.secret, String(body(ctx).code ?? '').trim(), now, null);
    if (matched === null) {
      await store.increment(key, LOGIN_WINDOW);
      return render(ctx, realm, t.enrollTitle, v.enrollForm(t, { action: ctx.path, csrf: csrf(ctx), secret: step.secret, uri: otpauthUri(step.secret, user.email, realm.displayName), error: t.invalidCode }), 401);
    }
    const codes = Array.from({ length: 10 }, newRecoveryCode);
    await store.putUser({ ...user, mfa: { secretEnc: deps.cipher.encrypt(step.secret), enabledAt: now.toISOString(), lastStep: matched }, recoveryHashes: codes.map(recoveryHash), updatedAt: now.toISOString() });
    await store.deleteStep(`acct#${ctx.params.key}`);
    await store.audit(realm.id, 'MFA_ENABLED', { userId: user.id, ip: ctx.ip }, settings.auditRetentionDays);
    render(ctx, realm, t.recoveryTitle, v.recoveryCodes(t, { codes, link: { href: `${base(realm)}/account`, label: t.continue } }));
  });

  async function secondFactorCheck(ctx: Ctx, realm: Realm, user: UserRecord): Promise<string | null> {
    const t = v.strings(realm.locale);
    if (!user.mfa?.enabledAt) return t.mfaOff;
    const key = `mfa#${realm.id}#${user.id}`;
    if (await tooMany([{ key, max: MAX_MFA_FAILURES }])) return t.tooMany;
    const matched = verifyTotp(deps.cipher.decrypt(user.mfa.secretEnc), String(body(ctx).code ?? '').trim(), deps.now(), user.mfa.lastStep);
    if (matched === null) {
      await store.increment(key, LOGIN_WINDOW);
      return t.invalidCode;
    }
    return null;
  }

  router.post('/realms/:realm/account/mfa/disable', parse, async (ctx) => {
    const realm = await realmOf(ctx.params.realm);
    const t = v.strings(realm.locale);
    const user = await reauth(ctx, realm);
    if (typeof user === 'string') return accountView(ctx, realm, { error: user }, 401);
    if (realm.mfa === 'required' || user.mfaRequired) return accountView(ctx, realm, { error: t.mfaRequiredByRealm, email: user.email }, 409);
    const problem = await secondFactorCheck(ctx, realm, user);
    if (problem) return accountView(ctx, realm, { error: problem, email: user.email }, 401);
    await store.putUser({ ...user, mfa: null, recoveryHashes: [], updatedAt: deps.now().toISOString() });
    await store.audit(realm.id, 'MFA_DISABLED', { userId: user.id, ip: ctx.ip }, settings.auditRetentionDays);
    accountView(ctx, realm, { notice: t.mfaOff, email: user.email });
  });

  router.post('/realms/:realm/account/mfa/recovery', parse, async (ctx) => {
    const realm = await realmOf(ctx.params.realm);
    const t = v.strings(realm.locale);
    const user = await reauth(ctx, realm);
    if (typeof user === 'string') return accountView(ctx, realm, { error: user }, 401);
    const problem = await secondFactorCheck(ctx, realm, user);
    if (problem) return accountView(ctx, realm, { error: problem, email: user.email }, 401);
    const codes = Array.from({ length: 10 }, newRecoveryCode);
    await store.putUser({ ...user, recoveryHashes: codes.map(recoveryHash), updatedAt: deps.now().toISOString() });
    await store.audit(realm.id, 'MFA_RECOVERY_CODES_RENEWED', { userId: user.id, ip: ctx.ip }, settings.auditRetentionDays);
    render(ctx, realm, t.recoveryTitle, v.recoveryCodes(t, { codes, link: { href: `${base(realm)}/account`, label: t.continue } }));
  });

  app.use(router.routes());
  app.use(router.allowedMethods());

  // ---- everything else under /realms/<realm>: the realm's OpenID Provider

  app.use(async (ctx) => {
    const m = /^\/realms\/([^/]+)(\/.*)?$/.exec(ctx.path);
    if (!m) throw new HttpError(404, 'not found');
    const realm = await realmOf(m[1]!);
    const provider = providerFor(realm);
    const prefix = `/realms/${realm.id}`;
    // A redirect URI the application gained a moment ago (a new realm joining it) may be missing from the copy in
    // memory: read the application again before oidc-provider refuses it.
    const clientId = ctx.query.client_id;
    const uri = ctx.query.redirect_uri ?? ctx.query.post_logout_redirect_uri;
    if (typeof clientId === 'string' && typeof uri === 'string') {
      const app = await deps.config.client(clientId);
      if (app && !app.redirectUris.includes(uri) && !app.postLogoutRedirectUris.includes(uri)) await deps.config.client(clientId, { reload: true });
    }
    // oidc-provider derives its mount path from `req.originalUrl` minus `req.url` (like koa-mount/express).
    (ctx.req as unknown as { originalUrl: string }).originalUrl = ctx.req.url!;
    ctx.req.url = ctx.req.url!.slice(prefix.length) || '/';
    ctx.respond = false;
    await provider.callback()(ctx.req, ctx.res);
  });

  return app;
}
