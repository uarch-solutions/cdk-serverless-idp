import Provider, { errors, type Configuration, type KoaContextWithOIDC } from 'oidc-provider';
import type { Deps } from './deps.js';
import { adapterFactory } from './oidc-adapter.js';
import type { Realm } from './store.js';
import { esc, logoutForm, message, page, strings } from './views.js';

export const ACCESS_TOKEN_TTL = 15 * 60;
const DAYS_30 = 30 * 24 * 3600;
export const issuerOf = (base: string, realm: string) => `${base}/realms/${realm}`;
/** Audience of an application's access tokens when it does not ask for a resource. */
export const appResource = (clientId: string) => `urn:idp:app:${clientId}`;

/**
 * One `oidc-provider` per realm (issuer `<base>/realms/<realm>`), built on first use and kept by the warm Lambda.
 * Access tokens are ES256 JWTs with the application as audience; the application's post-login hook adds its claims
 * (and may deny) on every access token.
 */
export function buildProvider(realm: Realm, deps: Deps): Provider {
  const { store, cipher, secret, settings } = deps;
  const t = strings(realm.locale);
  const cookieName = (k: string) => `_${k}_${realm.id}`.slice(0, 64);
  const signingAlgs: ('ES256' | 'RS256')[] = secret.jwks.keys.some((k) => k.kty === 'RSA') ? ['ES256', 'RS256'] : ['ES256'];

  const configuration: Configuration = {
    adapter: adapterFactory(store, deps.config, cipher, realm.id) as unknown as Configuration['adapter'],
    clients: [],
    clientDefaults: { grant_types: ['authorization_code'], id_token_signed_response_alg: 'ES256', response_types: ['code'], token_endpoint_auth_method: 'client_secret_basic' },
    jwks: secret.jwks as Configuration['jwks'],
    cookies: {
      keys: secret.cookieKeys,
      names: { session: cookieName('s'), interaction: cookieName('i'), resume: cookieName('r') },
      long: { signed: true, httpOnly: true, sameSite: 'lax' },
      short: { signed: true, httpOnly: true, sameSite: 'lax' },
    },
    claims: { openid: ['sub', 'amr', 'acr', 'auth_time'], email: ['email', 'email_verified'], profile: ['name'] },
    scopes: ['openid', 'offline_access', 'email', 'profile'],
    conformIdTokenClaims: false,
    // PKCE always, except for a confidential application registered without it (see ClientRecord.requirePkce).
    extraClientMetadata: { properties: ['require_pkce'] },
    pkce: { required: (_ctx, client) => (client as unknown as { require_pkce?: boolean }).require_pkce !== false },
    rotateRefreshToken: true,
    ttl: {
      AccessToken: ACCESS_TOKEN_TTL, AuthorizationCode: 60, ClientCredentials: ACCESS_TOKEN_TTL, IdToken: ACCESS_TOKEN_TTL,
      Interaction: 3600, Session: DAYS_30, Grant: DAYS_30, RefreshToken: DAYS_30,
    },
    findAccount: async (_ctx, sub) => {
      const u = await store.user(realm.id, sub);
      if (!u || u.status !== 'ACTIVE') return undefined;
      return {
        accountId: u.id,
        claims: async () => ({ sub: u.id, email: u.email, email_verified: u.emailVerified, name: u.name, realm: realm.id }),
      };
    },
    interactions: { url: (_ctx, interaction) => `/realms/${realm.id}/interaction/${interaction.uid}` },
    loadExistingGrant: async (ctx) => {
      const grantId = ctx.oidc.result?.consent?.grantId || ctx.oidc.session!.grantIdFor(ctx.oidc.client!.clientId);
      if (grantId) return ctx.oidc.provider.Grant.find(grantId);
      // First-party applications never show the consent screen.
      const app = await deps.config.client(ctx.oidc.client!.clientId);
      if (!app?.firstParty) return undefined;
      const grant = new ctx.oidc.provider.Grant({ clientId: ctx.oidc.client!.clientId, accountId: ctx.oidc.session!.accountId! });
      grant.addOIDCScope(app.scope);
      grant.addOIDCClaims(['email', 'email_verified', 'name']);
      grant.addResourceScope(appResource(app.clientId), app.scope);
      await grant.save();
      return grant;
    },
    extraTokenClaims: async (_ctx, token) => {
      const accountId = (token as { accountId?: string }).accountId;
      const clientId = (token as { clientId?: string }).clientId;
      if (!accountId || !clientId) return { realm: realm.id };
      const [app, user] = await Promise.all([deps.config.client(clientId), store.user(realm.id, accountId)]);
      if (!app || !user || user.status !== 'ACTIVE') throw new errors.InvalidGrant('account is not active');
      const r = await deps.hooks.call(app, { event: 'token', realm: realm.id, clientId, user: { sub: user.id, email: user.email, name: user.name, emailVerified: user.emailVerified } });
      if (!r.allow) throw new errors.InvalidGrant(r.reason ?? 'access denied by the application');
      return { realm: realm.id, ...r.claims };
    },
    features: {
      devInteractions: { enabled: false },
      claimsParameter: { enabled: true },
      revocation: { enabled: true },
      introspection: { enabled: true },
      clientCredentials: { enabled: true },
      resourceIndicators: {
        enabled: true,
        // Standard OpenID Connect by default: without `resource`, the access token is for the userinfo endpoint.
        // With `resource=urn:idp:app:<clientId>` it is an ES256 JWT for the application, with the hook claims.
        defaultResource: (_ctx, _client, oneOf) => oneOf,
        useGrantedResource: () => false,
        getResourceServerInfo: async (_ctx, resource, client) => {
          if (resource !== appResource(client.clientId)) throw new errors.InvalidTarget();
          const app = await deps.config.client(client.clientId);
          return {
            scope: app?.scope ?? 'openid',
            audience: client.clientId,
            accessTokenTTL: ACCESS_TOKEN_TTL,
            accessTokenFormat: 'jwt',
            jwt: { sign: { alg: 'ES256' } },
          };
        },
      },
      rpInitiatedLogout: {
        enabled: true,
        logoutSource: async (ctx, form) => {
          ctx.type = 'html';
          ctx.body = page({ realm, locale: realm.locale, title: t.logoutTitle, body: logoutForm(t, form) });
        },
        postLogoutSuccessSource: async (ctx) => {
          ctx.type = 'html';
          ctx.body = page({ realm, locale: realm.locale, title: t.logoutTitle, body: message({ title: t.logoutTitle, text: t.loggedOut, ...(realm.homeUrl ? { link: { href: realm.homeUrl, label: t.backToApp } } : {}) }) });
        },
      },
    },
    clientBasedCORS: (_ctx, origin, client) =>
      [...(client.redirectUris ?? []), ...(client.postLogoutRedirectUris ?? [])].some((u) => { try { return new URL(u).origin === origin; } catch { return false; } }),
    renderError: async (ctx, out) => {
      ctx.type = 'html';
      const text = out.error === 'access_denied' && out.error_description ? out.error_description : t.errorTitle;
      ctx.body = page({ realm, locale: realm.locale, title: t.errorTitle, body: message({ title: t.errorTitle, text: `${text}${out.error ? ` (${esc(out.error)})` : ''}`, error: true }) });
    },
    discovery: { service_documentation: 'https://github.com/uarch-solutions/cdk-serverless-idp' },
    // ES256 by default; RS256 too (required by OpenID Connect) when the installation has an RSA key (all since 0.4.0).
    enabledJWA: { idTokenSigningAlgValues: signingAlgs, userinfoSigningAlgValues: signingAlgs },
  };

  const provider = new Provider(issuerOf(settings.issuerBase, realm.id), configuration);
  provider.proxy = true;
  provider.on('server_error', (_ctx: KoaContextWithOIDC, err: Error) => console.error(JSON.stringify({ oidcServerError: err.message, stack: err.stack })));
  return provider;
}
