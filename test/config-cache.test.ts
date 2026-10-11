import { beforeAll, describe, expect, it, vi } from 'vitest';
import { ConfigCache } from '../runtime/config-cache.js';
import { Store, type ClientRecord, type Realm } from '../runtime/store.js';
import { createTable, dynamoClient, startDynamo, startIdp } from './support/harness.js';

const realm = (id: string, displayName = id): Realm => ({
  id, displayName, enabled: true, mfa: 'optional', locale: 'pt-BR', branding: {}, social: {}, socialAutoLink: false,
  createdAt: '2026-01-01T00:00:00Z', updatedAt: '2026-01-01T00:00:00Z',
});
const client = (redirectUris: string[], realms = ['*']): ClientRecord => ({
  clientId: 'app', name: 'App', firstParty: true, realms, redirectUris, postLogoutRedirectUris: [], grantTypes: ['authorization_code'],
  scope: 'openid', claimPrefix: 'app', createdAt: '2026-01-01T00:00:00Z', updatedAt: '2026-01-01T00:00:00Z',
} as unknown as ClientRecord);

describe('ConfigCache (realms and applications in memory, version check)', () => {
  let store: Store;
  let now = 0;
  let cache: ConfigCache;
  let reads: { mock: { calls: unknown[] } };

  beforeAll(async () => {
    startDynamo();
    const db = dynamoClient();
    await createTable(db, 'idp-config-cache');
    store = new Store('idp-config-cache', db);
    await store.putRealm(realm('acme', 'Acme'));
    await store.putClient(client(['https://acme.example/cb']));
    cache = new ConfigCache(store, 30_000, () => now);
    reads = vi.spyOn(store, 'realm');
  });

  it('reads a realm once and serves it from memory afterwards', async () => {
    expect((await cache.realm('acme'))?.displayName).toBe('Acme');
    expect((await cache.realm('acme'))?.displayName).toBe('Acme');
    expect(reads.mock.calls).toHaveLength(1);
  });

  it('a change applies after the next version check, not before', async () => {
    await store.putRealm(realm('acme', 'Acme Corp'));
    now += 10_000;
    expect((await cache.realm('acme'))?.displayName).toBe('Acme'); // still inside the check interval
    now += 30_000;
    expect((await cache.realm('acme'))?.displayName).toBe('Acme Corp');
  });

  it('a realm created a moment ago is found at once (misses are not cached)', async () => {
    expect(await cache.realm('beta')).toBeNull();
    await store.putRealm(realm('beta'));
    expect((await cache.realm('beta'))?.id).toBe('beta');
  });

  it('reload reads the application again (a redirect URI added a moment ago)', async () => {
    expect((await cache.client('app'))?.redirectUris).toEqual(['https://acme.example/cb']);
    await store.putClient(client(['https://acme.example/cb', 'https://beta.example/cb']));
    expect((await cache.client('app'))?.redirectUris).toHaveLength(1);
    expect((await cache.client('app', { reload: true }))?.redirectUris).toHaveLength(2);
  });

  it('with the check at 0 nothing is kept (tests and opt-out)', async () => {
    const off = new ConfigCache(store, 0);
    const spy = vi.spyOn(store, 'client');
    await off.client('app');
    await off.client('app');
    expect(spy).toHaveBeenCalledTimes(2);
  });

  it('counts people without reading them', async () => {
    await store.putUser({ realm: 'acme', id: 'u1', email: 'a@acme.example', name: 'A', status: 'ACTIVE', emailVerified: true } as never);
    await store.putUser({ realm: 'acme', id: 'u2', email: 'b@acme.example', name: 'B', status: 'ACTIVE', emailVerified: true } as never);
    expect(await store.countUsers('acme')).toBe(2);
  });
});

describe('web function with the cache on', () => {
  it('a redirect URI added to a warm application works at once; a realm joining it too', async () => {
    startDynamo();
    const idp = await startIdp('idp-config-cache-web', { configCheckMs: 60_000 });
    try {
      await idp.admin({ action: 'putRealm', realm: { id: 'acme', displayName: 'Acme' } });
      await idp.admin({ action: 'putClient', client: { clientId: 'app', name: 'App', redirectUris: ['http://localhost:4999/a'], realms: ['acme'], firstParty: true } });
      const auth = (realm: string, redirect: string) => fetch(`${idp.base}/realms/${realm}/auth?${new URLSearchParams({
        client_id: 'app', response_type: 'code', scope: 'openid', redirect_uri: redirect, code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', code_challenge_method: 'S256',
      })}`, { redirect: 'manual' });
      expect((await auth('acme', 'http://localhost:4999/a')).status).toBe(303); // warms the copies in memory
      await idp.admin({ action: 'addRedirectUris', clientId: 'app', redirectUris: ['http://localhost:4999/b'] });
      expect((await auth('acme', 'http://localhost:4999/b')).status).toBe(303);
      await idp.admin({ action: 'putRealm', realm: { id: 'beta', displayName: 'Beta' } });
      await idp.admin({ action: 'putClient', client: { clientId: 'app', realms: ['acme', 'beta'] } });
      expect((await auth('beta', 'http://localhost:4999/a')).status).toBe(303);
    } finally {
      await idp.close();
    }
  });
});
