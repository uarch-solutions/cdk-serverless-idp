// Provider for the OpenID Foundation conformance suite (TD-079): the same runtime as the Lambda, over HTTPS, on
// DynamoDB Local. Seeds one realm, two confidential applications registered for the suite and one person, and writes
// the suite configuration (with the application secrets) to CONFIG_OUT.
import { readFileSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:https';
import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { admin, newRuntimeSecret } from '../runtime/admin.js';
import { createApp } from '../runtime/app.js';
import { ConfigCache } from '../runtime/config-cache.js';
import { Cipher } from '../runtime/crypto.js';
import type { Deps } from '../runtime/deps.js';
import { HookCaller } from '../runtime/hooks.js';
import { MemoryMailer } from '../runtime/mail.js';
import { Store } from '../runtime/store.js';
import { createTable } from '../test/support/harness.js';

const env = (k: string, d?: string) => process.env[k] ?? d ?? (() => { throw new Error(`${k} missing`); })();
const ISSUER_BASE = env('ISSUER_BASE', 'https://idp:3443');
const SUITE = env('SUITE_BASE', 'https://localhost.emobix.co.uk:8443');
const ALIAS = env('ALIAS', 'serverless-idp');
const REALM = 'conformance';
const USER = { email: 'tester@example.com', name: 'Conformance Tester', password: 'Conformance-Test-123' };

const db = new DynamoDBClient({ endpoint: env('DYNAMO_ENDPOINT', 'http://dynamodb:8000'), region: 'us-east-1', credentials: { accessKeyId: 'x', secretAccessKey: 'x' } });
await createTable(db, 'idp');
const store = new Store('idp', db);
const secret = newRuntimeSecret();
const cipher = new Cipher(Buffer.from(secret.dataKey, 'base64'));
const settings = { tableName: 'idp', secretId: 'local', issuerBase: ISSUER_BASE, productName: 'Conformance', auditRetentionDays: 1, configCheckMs: 30_000 };
const deps: Deps = { settings, secret, store, config: new ConfigCache(store, settings.configCheckMs), cipher, mailer: new MemoryMailer(), hooks: new HookCaller(cipher, fetch), fetch, now: () => new Date() };
const run = async (e: Parameters<typeof admin>[0]) => {
  const r = (await admin(e, { ...deps, secretIo: { read: async () => secret, write: async () => undefined } })) as Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any
  if (!r.ok) throw new Error(`${e.action}: ${r.error} ${r.message ?? ''}`);
  return r;
};

await run({ action: 'putRealm', realm: { id: REALM, displayName: 'Conformance', locale: 'en', mfa: 'off' } as never });
const clients = [];
for (const [id, tokenEndpointAuthMethod] of [['conformance-1', 'client_secret_basic'], ['conformance-2', 'client_secret_basic'], ['conformance-post', 'client_secret_post']] as const) {
  const r = await run({
    action: 'putClient', client: {
      clientId: id, name: id, confidential: true, firstParty: true, requirePkce: false, tokenEndpointAuthMethod, // the Basic OP profile sends no PKCE
      realms: [REALM], scope: 'openid email profile offline_access',
      grantTypes: ['authorization_code', 'refresh_token'], redirectUris: [`${SUITE}/test/a/${ALIAS}/callback`], postLogoutRedirectUris: [`${SUITE}/test/a/${ALIAS}/post_logout_redirect`],
    },
  });
  clients.push({ client_id: id, client_secret: r.clientSecret as string });
}
const u = await run({ action: 'upsertUser', realm: REALM, user: { email: USER.email, name: USER.name, emailVerified: true } });
await run({ action: 'setPassword', realm: REALM, id: u.user.id, password: USER.password });

// The suite asks for screenshots where a person would judge the page (a second login, an error page); these commands
// take them, as in the suite's own CI configuration, so the run needs nobody.
const login = (match: string, screenshot = false) => ({
  task: 'Login', optional: true, match,
  commands: [
    ...(screenshot ? [['wait', 'xpath', '//*', 10, 'Sign in', 'update-image-placeholder-optional']] : []),
    ['text', 'name', 'email', USER.email, 'optional'], ['text', 'name', 'password', USER.password, 'optional'], ['click', 'css', 'button[type=submit]'],
  ],
});
const AUTH = `${ISSUER_BASE}/realms/${REALM}/auth*`;
const INTERACTION = `${ISSUER_BASE}/realms/${REALM}/interaction*`;
const complete = { task: 'Verify Complete', match: '*/test/*/callback*', commands: [['wait', 'id', 'submission_complete', 10]] };
const signIn = (screenshot = false) => [{ match: AUTH, tasks: [login(INTERACTION, screenshot), complete] }];
const errorPage = [{ match: AUTH, tasks: [{ task: 'Expect an error page', match: AUTH, commands: [['wait', 'xpath', '//*', 10, 'Something went wrong', 'update-image-placeholder']] }] }];
writeFileSync(env('CONFIG_OUT', 'conformance/out/config.json'), JSON.stringify({
  alias: ALIAS,
  description: 'cdk-serverless-idp',
  server: { discoveryUrl: `${ISSUER_BASE}/realms/${REALM}/.well-known/openid-configuration` },
  client: { ...clients[0], client_name: 'first' },
  client2: { ...clients[1], client_name: 'second' },
  client_secret_post: { ...clients[2], client_name: 'post' },
  browser: signIn(),
  override: {
    'oidcc-prompt-login': { browser: signIn(true) },
    'oidcc-max-age-1': { browser: signIn(true) },
    'oidcc-ensure-registered-redirect-uri': { browser: errorPage },
    'oidcc-ensure-redirect-uri-in-authorization-request': { browser: errorPage },
    'oidcc-redirect-uri-query-added': { browser: errorPage },
    'oidcc-redirect-uri-query-mismatch': { browser: errorPage },
    // Request objects are not supported; with the redirect URI only inside the request object, the error is a page.
    'oidcc-ensure-request-object-with-redirect-uri': { browser: errorPage },
  },
}, null, 2));

const server = createServer({ key: readFileSync(env('TLS_KEY')), cert: readFileSync(env('TLS_CERT')) }, createApp(deps).callback());
server.listen(Number(env('PORT', '3443')), '0.0.0.0', () => console.log(`conformance provider on ${ISSUER_BASE}/realms/${REALM}`));
