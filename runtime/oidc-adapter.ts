import type { ClientRecord, Store } from './store.js';
import type { Cipher } from './crypto.js';

type Payload = Record<string, unknown> & { grantId?: string; uid?: string; userCode?: string; accountId?: string; consumed?: number };

/** Clients are not stored as OIDC models: they come from the application records, filtered by realm. */
export function clientMetadata(c: ClientRecord, cipher: Cipher) {
  const confidential = !!c.secretEnc;
  return {
    client_id: c.clientId,
    client_name: c.name,
    ...(confidential ? { client_secret: cipher.decrypt(c.secretEnc!) } : {}),
    token_endpoint_auth_method: confidential ? 'client_secret_basic' : 'none',
    redirect_uris: c.redirectUris,
    post_logout_redirect_uris: c.postLogoutRedirectUris,
    grant_types: c.grantTypes,
    response_types: c.grantTypes.includes('authorization_code') ? ['code'] : [],
    scope: c.scope,
  };
}

export const clientAllowedIn = (c: ClientRecord, realm: string) => c.realms.includes('*') || c.realms.includes(realm);

/** `oidc-provider` adapter on the DynamoDB table (one per model, bound to the realm). */
export function adapterFactory(store: Store, cipher: Cipher, realm: string) {
  return class DynamoAdapter {
    constructor(private readonly model: string) {}

    async upsert(id: string, payload: Payload, expiresIn?: number) {
      await store.oidcPut(this.model, id, payload, expiresIn, {
        grantId: payload.grantId,
        uid: this.model === 'Session' ? payload.uid : undefined,
        userCode: payload.userCode,
        account: (this.model === 'Session' || this.model === 'Grant') && payload.accountId ? `${realm}#${payload.accountId}` : undefined,
      });
    }

    async find(id: string) {
      if (this.model === 'Client') {
        const c = await store.client(id);
        return c && clientAllowedIn(c, realm) ? clientMetadata(c, cipher) : undefined;
      }
      return store.oidcGet(this.model, id);
    }

    findByUid(uid: string) { return store.oidcByIndex('gsi2', `UID#${uid}`); }
    findByUserCode(userCode: string) { return store.oidcByIndex('gsi2', `USERCODE#${userCode}`); }
    destroy(id: string) { return store.oidcDelete(this.model, id); }
    consume(id: string) { return store.oidcConsume(this.model, id); }
    revokeByGrantId(grantId: string) { return store.deleteByIndex('gsi1', `GRANT#${grantId}`); }
  };
}
