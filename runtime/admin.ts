import { generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto';
import { Cipher, randomToken, sha256 } from './crypto.js';
import type { Deps, RuntimeSecret } from './deps.js';
import { hashPassword, passwordProblem } from './passwords.js';
import type { ClientRecord, Hook, IdentityRecord, Realm, UserRecord } from './store.js';
import { strings } from './views.js';

/**
 * Administration API, invoked only through `lambda:InvokeFunction` (IAM): there is no public admin route. Every
 * action returns `{ ok: true, ... }` or `{ ok: false, error: CODE, message }`.
 */
export type AdminEvent =
  | { action: 'bootstrap' }
  | { action: 'rotateKeys' }
  | { action: 'putRealm'; realm: Partial<Omit<Realm, 'social'>> & { id: string; social?: Record<string, { clientId: string; clientSecret?: string; enabled: boolean }> } }
  | { action: 'getRealm'; realm: string }
  | { action: 'putClient'; client: Partial<Omit<ClientRecord, 'secretEnc' | 'hook'>> & { clientId: string; confidential?: boolean; hook?: (Omit<Hook, 'secretEnc'> & { secret?: string }) | null } }
  | { action: 'rotateClientSecret'; clientId: string }
  | { action: 'getClient'; clientId: string }
  | { action: 'upsertUser'; realm: string; user: { id?: string; email: string; name: string; status?: UserRecord['status']; emailVerified?: boolean; passwordHash?: string; passwordChangeRequired?: boolean; mfaRequired?: boolean; mfaGraceUntil?: string | null } }
  | { action: 'addRedirectUris'; clientId: string; redirectUris?: string[]; postLogoutRedirectUris?: string[] }
  | { action: 'importUsers'; realm: string; users: ImportUser[] }
  | { action: 'getUser'; realm: string; id?: string; email?: string }
  | { action: 'setPassword'; realm: string; id: string; password: string; temporary?: boolean }
  | { action: 'invite'; realm: string; id: string; kind?: 'invite' | 'reset'; returnTo?: string; send?: boolean; ttlHours?: number }
  | { action: 'resetMfa'; realm: string; id: string }
  | { action: 'revokeSessions'; realm: string; id: string }
  | { action: 'deleteUser'; realm: string; id: string }
  | { action: 'audit'; realm: string; limit?: number }
  | { action: 'countUsers'; realm: string };

export interface ImportUser {
  id: string; email: string; name: string; status: UserRecord['status']; emailVerified: boolean; passwordHash: string | null;
  /** Base32 TOTP secret in clear (encrypted here with the data key) and when it was turned on. */
  mfaSecret?: string | null; mfaEnabledAt?: string | null; mfaLastStep?: number | null;
  /** sha256 of the lowercase recovery codes. */
  recoveryHashes?: string[];
  mfaRequired?: boolean; mfaGraceUntil?: string | null; passwordChangeRequired?: boolean;
  identities?: { provider: string; subject: string; email: string | null }[];
}

class AdminError extends Error { constructor(readonly code: string, message: string) { super(message); } }
const nowIso = () => new Date().toISOString();
const REALM_ID = /^[a-z0-9][a-z0-9-]{0,62}$/;
const CLIENT_ID = /^[a-z0-9][a-z0-9._-]{1,62}$/;

export function newSigningKey() {
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  return { ...privateKey.export({ format: 'jwk' }), kid: randomToken(8), alg: 'ES256', use: 'sig' } as Record<string, unknown>;
}

/** First secret: one signing key, two cookie keys, the data key and the CloudFront origin header value. */
export function newRuntimeSecret(originVerify?: string): RuntimeSecret {
  return {
    jwks: { keys: [newSigningKey()] },
    cookieKeys: [randomToken(32), randomToken(32)],
    dataKey: randomBytes(32).toString('base64'),
    ...(originVerify ? { originVerify } : {}),
  };
}

export interface SecretIo { read(): Promise<RuntimeSecret | null>; write(s: RuntimeSecret): Promise<void> }

export async function admin(event: AdminEvent, deps: Omit<Deps, 'secret' | 'cipher'> & { secret: RuntimeSecret | null; cipher: Cipher | null; secretIo: SecretIo; originVerify?: string }) {
  try {
    return { ok: true, ...(await run(event, deps)) };
  } catch (e) {
    if (e instanceof AdminError) return { ok: false, error: e.code, message: e.message };
    console.error(JSON.stringify({ adminError: (e as Error).message, stack: (e as Error).stack }));
    return { ok: false, error: 'INTERNAL', message: (e as Error).message };
  }
}

async function run(event: AdminEvent, deps: Parameters<typeof admin>[1]): Promise<Record<string, unknown>> {
  const { store, settings } = deps;
  if (event.action === 'bootstrap') {
    const current = await deps.secretIo.read();
    if (current) {
      // Keeps the keys; only aligns the CloudFront origin header with the deployed value.
      if (deps.originVerify && current.originVerify !== deps.originVerify) await deps.secretIo.write({ ...current, originVerify: deps.originVerify });
      return { created: false };
    }
    await deps.secretIo.write(newRuntimeSecret(deps.originVerify));
    return { created: true };
  }
  if (event.action === 'rotateKeys') {
    const current = await deps.secretIo.read();
    if (!current) throw new AdminError('NOT_BOOTSTRAPPED', 'run bootstrap first');
    // New key signs; the previous one stays published to verify tokens issued before.
    const keys = [newSigningKey(), current.jwks.keys[0]!];
    await deps.secretIo.write({ ...current, jwks: { keys }, cookieKeys: [randomToken(32), current.cookieKeys[0]!] });
    return { kids: keys.map((k) => k.kid) };
  }
  const cipher = deps.cipher;
  if (!cipher) throw new AdminError('NOT_BOOTSTRAPPED', 'run bootstrap first');
  if (!settings.issuerBase) {
    // No custom domain: the public function learns its CloudFront name on the first request.
    settings.issuerBase = (await store.installation())?.issuerBase ?? '';
    if (!settings.issuerBase && event.action === 'invite') throw new AdminError('NOT_READY', 'open the provider URL once so it learns its address');
  }

  switch (event.action) {
    case 'putRealm': {
      const input = event.realm;
      if (!REALM_ID.test(input.id)) throw new AdminError('INVALID_REALM', 'realm id: lowercase letters, digits and -');
      const current = await store.realm(input.id);
      const social: Realm['social'] = { ...(current?.social ?? {}) };
      for (const [p, s] of Object.entries(input.social ?? {})) {
        if (p !== 'google' && p !== 'facebook') continue;
        const secretEnc = s.clientSecret ? cipher.encrypt(s.clientSecret) : current?.social[p]?.clientSecretEnc;
        if (s.enabled && !secretEnc) throw new AdminError('INVALID_SOCIAL', `${p}: client secret required`);
        social[p] = { clientId: s.clientId, clientSecretEnc: secretEnc ?? '', enabled: s.enabled };
      }
      const realm: Realm = {
        id: input.id, displayName: input.displayName ?? current?.displayName ?? input.id, enabled: input.enabled ?? current?.enabled ?? true,
        mfa: input.mfa ?? current?.mfa ?? 'optional', locale: input.locale ?? current?.locale ?? 'pt-BR', branding: input.branding ?? current?.branding ?? {},
        social, socialAutoLink: input.socialAutoLink ?? current?.socialAutoLink ?? false, homeUrl: input.homeUrl ?? current?.homeUrl,
        createdAt: current?.createdAt ?? nowIso(), updatedAt: nowIso(),
      };
      await store.putRealm(realm);
      return { realm: publicRealm(realm), created: !current };
    }
    case 'getRealm': {
      const realm = await store.realm(event.realm);
      if (!realm) throw new AdminError('REALM_NOT_FOUND', 'realm not found');
      return { realm: publicRealm(realm) };
    }
    case 'putClient': {
      const input = event.client;
      if (!CLIENT_ID.test(input.clientId)) throw new AdminError('INVALID_CLIENT', 'client id: lowercase letters, digits, . _ -');
      const current = await store.client(input.clientId);
      const confidential = input.confidential ?? (current ? !!current.secretEnc : true);
      let secret: string | undefined;
      let secretEnc = current?.secretEnc ?? null;
      if (confidential && !secretEnc) { secret = randomToken(32); secretEnc = cipher.encrypt(secret); }
      if (!confidential) secretEnc = null;
      const hookInput = input.hook === undefined ? undefined : input.hook;
      const hook: Hook | null = hookInput === undefined ? current?.hook ?? null : hookInput === null ? null : {
        url: hookInput.url, lambdaArn: hookInput.lambdaArn, onError: hookInput.onError ?? 'deny', timeoutMs: Math.min(Math.max(hookInput.timeoutMs ?? 2000, 200), 5000),
        secretEnc: hookInput.secret ? cipher.encrypt(hookInput.secret) : current?.hook?.secretEnc,
      };
      if (hook?.url && !/^https:\/\//.test(hook.url) && !/^http:\/\/(localhost|127\.0\.0\.1)/.test(hook.url)) throw new AdminError('INVALID_HOOK', 'hook url must be https');
      const redirectUris = input.redirectUris ?? current?.redirectUris ?? [];
      for (const u of redirectUris) if (!/^https:\/\//.test(u) && !/^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?\//.test(u)) throw new AdminError('INVALID_REDIRECT_URI', `redirect uri must be https: ${u}`);
      const client: ClientRecord = {
        clientId: input.clientId, name: input.name ?? current?.name ?? input.clientId, secretEnc, redirectUris,
        postLogoutRedirectUris: input.postLogoutRedirectUris ?? current?.postLogoutRedirectUris ?? [],
        realms: input.realms ?? current?.realms ?? [], firstParty: input.firstParty ?? current?.firstParty ?? false,
        grantTypes: input.grantTypes ?? current?.grantTypes ?? ['authorization_code', 'refresh_token'],
        scope: input.scope ?? current?.scope ?? 'openid email profile offline_access', claimPrefix: input.claimPrefix ?? current?.claimPrefix ?? input.clientId,
        hook, createdAt: current?.createdAt ?? nowIso(), updatedAt: nowIso(),
      };
      await store.putClient(client);
      return { client: publicClient(client), ...(secret ? { clientSecret: secret } : {}) };
    }
    case 'addRedirectUris': {
      // Adds without a read-modify-write on the caller side (one realm at a time joins a shared application).
      const current = await store.client(event.clientId);
      if (!current) throw new AdminError('CLIENT_NOT_FOUND', 'client not found');
      for (const u of [...(event.redirectUris ?? []), ...(event.postLogoutRedirectUris ?? [])]) {
        if (!/^https:\/\//.test(u) && !/^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?\//.test(u)) throw new AdminError('INVALID_REDIRECT_URI', `redirect uri must be https: ${u}`);
      }
      const merge = (a: string[], b?: string[]) => [...new Set([...a, ...(b ?? [])])];
      await store.putClient({
        ...current, redirectUris: merge(current.redirectUris, event.redirectUris), postLogoutRedirectUris: merge(current.postLogoutRedirectUris, event.postLogoutRedirectUris), updatedAt: nowIso(),
      });
      return { redirectUris: merge(current.redirectUris, event.redirectUris).length };
    }
    case 'rotateClientSecret': {
      const current = await store.client(event.clientId);
      if (!current) throw new AdminError('CLIENT_NOT_FOUND', 'client not found');
      const secret = randomToken(32);
      await store.putClient({ ...current, secretEnc: cipher.encrypt(secret), updatedAt: nowIso() });
      return { clientSecret: secret };
    }
    case 'getClient': {
      const c = await store.client(event.clientId);
      if (!c) throw new AdminError('CLIENT_NOT_FOUND', 'client not found');
      return { client: publicClient(c) };
    }
    case 'upsertUser': {
      await realmOrFail(deps, event.realm);
      const email = event.user.email.trim().toLowerCase();
      const byEmail = await store.userByEmail(event.realm, email);
      const current = event.user.id ? await store.user(event.realm, event.user.id) : byEmail;
      if (byEmail && current && byEmail.id !== current.id) throw new AdminError('EMAIL_IN_USE', 'another person in this realm uses this e-mail');
      if (byEmail && !current) throw new AdminError('EMAIL_IN_USE', 'another person in this realm uses this e-mail');
      // A pre-hashed argon2 password (e.g. set by the application's administrator) replaces the current one.
      if (event.user.passwordHash !== undefined && !event.user.passwordHash.startsWith('$argon2')) throw new AdminError('INVALID_HASH', 'only argon2 PHC hashes are accepted');
      const user: UserRecord = {
        id: current?.id ?? event.user.id ?? randomUUID(), realm: event.realm, email, name: event.user.name,
        passwordHash: event.user.passwordHash ?? current?.passwordHash ?? null, status: event.user.status ?? current?.status ?? 'ACTIVE',
        emailVerified: current && current.email === email ? current.emailVerified || !!event.user.emailVerified : !!event.user.emailVerified,
        mfa: current?.mfa ?? null, recoveryHashes: current?.recoveryHashes ?? [],
        mfaRequired: event.user.mfaRequired ?? current?.mfaRequired ?? false,
        passwordChangeRequired: event.user.passwordChangeRequired ?? (event.user.passwordHash ? false : current?.passwordChangeRequired ?? false),
        mfaGraceUntil: event.user.mfaGraceUntil !== undefined ? event.user.mfaGraceUntil : current?.mfaGraceUntil ?? null,
        createdAt: current?.createdAt ?? nowIso(), updatedAt: nowIso(),
      };
      await store.putUser(user);
      const passwordChanged = !!event.user.passwordHash && current?.passwordHash !== event.user.passwordHash;
      if ((current && current.status === 'ACTIVE' && user.status === 'DISABLED') || (current && passwordChanged)) await store.deleteByIndex('gsi3', `ACCOUNT#${event.realm}#${user.id}`);
      await store.audit(event.realm, current ? 'USER_UPDATED' : 'USER_CREATED', { userId: user.id, by: 'admin' }, settings.auditRetentionDays);
      return { user: publicUser(user), created: !current };
    }
    case 'importUsers': {
      await realmOrFail(deps, event.realm);
      let imported = 0;
      for (const u of event.users) {
        const email = u.email.trim().toLowerCase();
        const clash = await store.userByEmail(event.realm, email);
        if (clash && clash.id !== u.id) throw new AdminError('EMAIL_IN_USE', `e-mail of ${u.id} belongs to ${clash.id}`);
        const current = await store.user(event.realm, u.id);
        await store.putUser({
          id: u.id, realm: event.realm, email, name: u.name, passwordHash: u.passwordHash, status: u.status, emailVerified: u.emailVerified,
          mfa: u.mfaSecret ? { secretEnc: cipher.encrypt(u.mfaSecret), enabledAt: u.mfaEnabledAt ?? null, lastStep: u.mfaLastStep ?? null } : null,
          recoveryHashes: u.recoveryHashes ?? [], mfaRequired: u.mfaRequired ?? false, mfaGraceUntil: u.mfaGraceUntil ?? null,
          passwordChangeRequired: u.passwordChangeRequired ?? false,
          createdAt: current?.createdAt ?? nowIso(), updatedAt: nowIso(),
        });
        for (const i of u.identities ?? []) {
          const identity: IdentityRecord = { realm: event.realm, userId: u.id, provider: i.provider.toLowerCase(), subject: i.subject, email: i.email, createdAt: nowIso() };
          await store.putIdentity(identity);
        }
        imported++;
      }
      await store.audit(event.realm, 'USERS_IMPORTED', { count: imported }, settings.auditRetentionDays);
      return { imported };
    }
    case 'getUser': {
      const u = event.id ? await store.user(event.realm, event.id) : event.email ? await store.userByEmail(event.realm, event.email) : null;
      if (!u) throw new AdminError('USER_NOT_FOUND', 'user not found');
      return { user: publicUser(u), identities: (await store.identitiesOf(event.realm, u.id)).map((i) => ({ provider: i.provider, email: i.email })) };
    }
    case 'setPassword': {
      const u = await userOrFail(deps, event.realm, event.id);
      if (passwordProblem(event.password)) throw new AdminError('WEAK_PASSWORD', 'password must have at least 8 characters');
      await store.putUser({ ...u, passwordHash: await hashPassword(event.password), passwordChangeRequired: !!event.temporary, updatedAt: nowIso() });
      await store.deleteByIndex('gsi3', `ACCOUNT#${event.realm}#${u.id}`);
      await store.audit(event.realm, 'PASSWORD_SET_BY_ADMIN', { userId: u.id }, settings.auditRetentionDays);
      return {};
    }
    case 'invite': {
      const realm = await realmOrFail(deps, event.realm);
      const u = await userOrFail(deps, event.realm, event.id);
      const kind = event.kind ?? 'invite';
      const token = randomToken(32);
      const ttlHours = Math.min(Math.max(event.ttlHours ?? (kind === 'invite' ? 168 : 1), 1), 720);
      await store.putActionToken(sha256(token), { realm: event.realm, userId: u.id, kind, returnTo: event.returnTo ?? realm.homeUrl ?? null }, ttlHours * 3600);
      const url = `${settings.issuerBase}/realms/${event.realm}/action/${token}`;
      const expiresAt = new Date(Date.now() + ttlHours * 3600_000).toISOString();
      let emailed = false;
      if (event.send !== false && deps.mailer.enabled) {
        const t = strings(realm.locale);
        await deps.mailer.send({ to: u.email, subject: `${kind === 'invite' ? t.inviteTitle : t.resetTitle} — ${realm.displayName}`, text: `${u.name},\n\n${url}\n` });
        emailed = true;
      }
      await store.audit(event.realm, kind === 'invite' ? 'INVITE_SENT' : 'PASSWORD_RESET_LINK', { userId: u.id, emailed }, settings.auditRetentionDays);
      return { url, expiresAt, emailed };
    }
    case 'resetMfa': {
      const u = await userOrFail(deps, event.realm, event.id);
      await store.putUser({ ...u, mfa: null, recoveryHashes: [], updatedAt: nowIso() });
      await store.audit(event.realm, 'MFA_RESET_BY_ADMIN', { userId: u.id }, settings.auditRetentionDays);
      return {};
    }
    case 'revokeSessions': {
      await store.deleteByIndex('gsi3', `ACCOUNT#${event.realm}#${event.id}`);
      await store.audit(event.realm, 'SESSIONS_REVOKED', { userId: event.id }, settings.auditRetentionDays);
      return {};
    }
    case 'deleteUser': {
      for (const i of await store.identitiesOf(event.realm, event.id)) await store.deleteIdentity(event.realm, i.provider, i.subject);
      await store.deleteByIndex('gsi3', `ACCOUNT#${event.realm}#${event.id}`);
      await store.deleteUser(event.realm, event.id);
      await store.audit(event.realm, 'USER_DELETED', { userId: event.id }, settings.auditRetentionDays);
      return {};
    }
    case 'audit':
      return { events: await store.auditTrail(event.realm, Math.min(event.limit ?? 100, 500)) };
    case 'countUsers':
      return { count: (await store.usersOf(event.realm)).length };
    default:
      throw new AdminError('UNKNOWN_ACTION', `unknown action ${(event as { action: string }).action}`);
  }
}

async function realmOrFail(deps: Parameters<typeof admin>[1], id: string) {
  const r = await deps.store.realm(id);
  if (!r) throw new AdminError('REALM_NOT_FOUND', 'realm not found');
  return r;
}
async function userOrFail(deps: Parameters<typeof admin>[1], realm: string, id: string) {
  const u = await deps.store.user(realm, id);
  if (!u) throw new AdminError('USER_NOT_FOUND', 'user not found');
  return u;
}

const publicRealm = (r: Realm) => ({ ...r, social: Object.fromEntries(Object.entries(r.social).map(([k, s]) => [k, { clientId: s!.clientId, enabled: s!.enabled }])) });
const publicClient = (c: ClientRecord) => ({ ...c, secretEnc: undefined, confidential: !!c.secretEnc, hook: c.hook ? { ...c.hook, secretEnc: undefined, hasSecret: !!c.hook.secretEnc } : null });
const publicUser = (u: UserRecord) => ({
  id: u.id, realm: u.realm, email: u.email, name: u.name, status: u.status, emailVerified: u.emailVerified, mfaEnabled: !!u.mfa?.enabledAt,
  mfaRequired: !!u.mfaRequired, mfaGraceUntil: u.mfaGraceUntil ?? null, passwordChangeRequired: !!u.passwordChangeRequired,
  hasPassword: !!u.passwordHash, createdAt: u.createdAt, updatedAt: u.updatedAt,
});
