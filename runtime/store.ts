import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import {
  BatchWriteCommand, DeleteCommand, DynamoDBDocumentClient, GetCommand, PutCommand, QueryCommand, UpdateCommand,
} from '@aws-sdk/lib-dynamodb';

/**
 * Single-table DynamoDB storage (on-demand, TTL on `ttl`). Keys:
 *
 * | item            | pk                          | sk                              | gsi1pk                         | gsi3pk              |
 * |-----------------|-----------------------------|---------------------------------|--------------------------------|---------------------|
 * | realm           | REALM#<realm>               | META                            |                                |                     |
 * | user            | REALM#<realm>               | USER#<id>                       |                                |                     |
 * | e-mail pointer  | EMAIL#<realm>#<email>       | META (userId; unique per realm) |                                |                     |
 * | social identity | REALM#<realm>               | IDP#<provider>#<subject>        | USERIDP#<realm>#<userId>       |                     |
 * | audit event     | REALM#<realm>               | AUDIT#<iso>#<rand>              |                                |                     |
 * | client (app)    | CLIENT#<clientId>           | META                            |                                |                     |
 * | action token    | ACTION#<sha256>             | META                            |                                |                     |
 * | counter         | COUNT#<key>                 | META                            |                                |                     |
 * | pending step    | STEP#<key>                  | META                            |                                |                     |
 * | OIDC model      | OIDC#<Model>#<id>           | META                            | GRANT#<grantId>                | ACCOUNT#<realm>#<sub>|
 *
 * Strongly consistent pointers `OIDCREF#UID#<uid>` / `OIDCREF#USERCODE#<code>` find sessions and device codes (an
 * index would be eventually consistent, and a session is read right after it is written).
 */
export type MfaPolicy = 'off' | 'optional' | 'required';
export interface Realm {
  id: string; displayName: string; enabled: boolean; mfa: MfaPolicy; locale: 'pt-BR' | 'en';
  branding: { color?: string; logoUrl?: string };
  /** Upstream social login (client secret encrypted with the data key). */
  social: Partial<Record<'google' | 'facebook', { clientId: string; clientSecretEnc: string; enabled: boolean }>>;
  /** Link a social login to an existing account with the same verified e-mail. */
  socialAutoLink: boolean;
  /** Where "back to the application" goes after a password reset or invite (e.g. the app login page). */
  homeUrl?: string;
  createdAt: string; updatedAt: string;
}
export interface Hook {
  url?: string; lambdaArn?: string; secretEnc?: string; onError: 'deny' | 'allow'; timeoutMs: number;
}
export interface ClientRecord {
  clientId: string; name: string; secretEnc: string | null; redirectUris: string[]; postLogoutRedirectUris: string[];
  /** Realms this application may sign in to (`*` = all). */
  realms: string[];
  firstParty: boolean; grantTypes: string[]; scope: string; claimPrefix: string; hook: Hook | null;
  createdAt: string; updatedAt: string;
}
export interface UserRecord {
  id: string; realm: string; email: string; name: string; passwordHash: string | null; status: 'ACTIVE' | 'DISABLED';
  emailVerified: boolean;
  mfa: { secretEnc: string; enabledAt: string | null; lastStep: number | null } | null;
  recoveryHashes: string[];
  createdAt: string; updatedAt: string;
}
export interface IdentityRecord { realm: string; userId: string; provider: string; subject: string; email: string | null; createdAt: string }
export interface ActionToken { realm: string; userId: string; kind: 'invite' | 'reset'; returnTo?: string | null }

const nowIso = () => new Date().toISOString();
const ttlIn = (seconds: number) => Math.floor(Date.now() / 1000) + seconds;
const emailKey = (realm: string, email: string) => `EMAIL#${realm}#${email.trim().toLowerCase()}`;

export class Store {
  readonly doc: DynamoDBDocumentClient;

  constructor(readonly table: string, client?: DynamoDBClient) {
    this.doc = DynamoDBDocumentClient.from(client ?? new DynamoDBClient({}), { marshallOptions: { removeUndefinedValues: true } });
  }

  private async get<T>(pk: string, sk = 'META'): Promise<T | null> {
    const r = await this.doc.send(new GetCommand({ TableName: this.table, Key: { pk, sk }, ConsistentRead: true }));
    const item = r.Item as { data?: T; ttl?: number } | undefined;
    if (!item || (item.ttl && item.ttl < Date.now() / 1000)) return null; // TTL deletion is lazy in DynamoDB
    return item.data ?? null;
  }

  private async put(item: Record<string, unknown>) {
    await this.doc.send(new PutCommand({ TableName: this.table, Item: item }));
  }

  // ---- installation (issuer base learned from CloudFront when there is no custom domain)

  installation() { return this.get<{ issuerBase: string }>('INSTALL'); }
  async putInstallation(issuerBase: string) { await this.put({ pk: 'INSTALL', sk: 'META', data: { issuerBase } }); }

  // ---- realms

  realm(id: string) { return this.get<Realm>(`REALM#${id}`); }
  async putRealm(r: Realm) { await this.put({ pk: `REALM#${r.id}`, sk: 'META', data: r }); }

  // ---- clients

  client(id: string) { return this.get<ClientRecord>(`CLIENT#${id}`); }
  async putClient(c: ClientRecord) { await this.put({ pk: `CLIENT#${c.clientId}`, sk: 'META', data: c }); }

  // ---- users

  user(realm: string, id: string) { return this.get<UserRecord>(`REALM#${realm}`, `USER#${id}`); }

  /** Strongly consistent (pointer item): right after a person is created or imported they can sign in. */
  async userByEmail(realm: string, email: string): Promise<UserRecord | null> {
    const r = await this.doc.send(new GetCommand({ TableName: this.table, Key: { pk: emailKey(realm, email), sk: 'META' }, ConsistentRead: true }));
    const id = r.Item?.userId as string | undefined;
    return id ? this.user(realm, id) : null;
  }

  async putUser(u: UserRecord) {
    u.email = u.email.trim().toLowerCase();
    const before = await this.user(u.realm, u.id);
    await this.put({ pk: `REALM#${u.realm}`, sk: `USER#${u.id}`, data: u });
    if (before && before.email !== u.email) {
      await this.doc.send(new DeleteCommand({ TableName: this.table, Key: { pk: emailKey(u.realm, before.email), sk: 'META' }, ConditionExpression: 'userId = :id', ExpressionAttributeValues: { ':id': u.id } })).catch(() => undefined);
    }
    if (!before || before.email !== u.email) {
      // One person per e-mail in a realm, even with concurrent writes.
      await this.doc.send(new PutCommand({
        TableName: this.table, Item: { pk: emailKey(u.realm, u.email), sk: 'META', userId: u.id },
        ConditionExpression: 'attribute_not_exists(pk) OR userId = :id', ExpressionAttributeValues: { ':id': u.id },
      }));
    }
  }

  async deleteUser(realm: string, id: string) {
    const u = await this.user(realm, id);
    await this.doc.send(new DeleteCommand({ TableName: this.table, Key: { pk: `REALM#${realm}`, sk: `USER#${id}` } }));
    if (u) await this.doc.send(new DeleteCommand({ TableName: this.table, Key: { pk: emailKey(realm, u.email), sk: 'META' } }));
  }

  // ---- social identities

  identity(realm: string, provider: string, subject: string) { return this.get<IdentityRecord>(`REALM#${realm}`, `IDP#${provider}#${subject}`); }

  async identitiesOf(realm: string, userId: string): Promise<IdentityRecord[]> {
    const r = await this.doc.send(new QueryCommand({
      TableName: this.table, IndexName: 'gsi1', KeyConditionExpression: 'gsi1pk = :k', ExpressionAttributeValues: { ':k': `USERIDP#${realm}#${userId}` },
    }));
    return (r.Items ?? []).map((i) => i.data as IdentityRecord);
  }

  async putIdentity(i: IdentityRecord) {
    await this.put({ pk: `REALM#${i.realm}`, sk: `IDP#${i.provider}#${i.subject}`, gsi1pk: `USERIDP#${i.realm}#${i.userId}`, gsi1sk: `IDP#${i.provider}`, data: i });
  }

  async deleteIdentity(realm: string, provider: string, subject: string) {
    await this.doc.send(new DeleteCommand({ TableName: this.table, Key: { pk: `REALM#${realm}`, sk: `IDP#${provider}#${subject}` } }));
  }

  // ---- single-use action tokens (invite, password reset), stored by hash

  actionToken(hash: string) { return this.get<ActionToken>(`ACTION#${hash}`); }
  async putActionToken(hash: string, t: ActionToken, seconds: number) { await this.put({ pk: `ACTION#${hash}`, sk: 'META', ttl: ttlIn(seconds), data: t }); }
  async deleteActionToken(hash: string) { await this.doc.send(new DeleteCommand({ TableName: this.table, Key: { pk: `ACTION#${hash}`, sk: 'META' } })); }

  // ---- short-lived state (pending second factor, upstream login state)

  step<T>(key: string) { return this.get<T>(`STEP#${key}`); }
  async putStep(key: string, data: unknown, seconds: number) { await this.put({ pk: `STEP#${key}`, sk: 'META', ttl: ttlIn(seconds), data }); }
  async deleteStep(key: string) { await this.doc.send(new DeleteCommand({ TableName: this.table, Key: { pk: `STEP#${key}`, sk: 'META' } })); }

  // ---- counters for rate limiting (fixed window)

  async count(key: string): Promise<number> {
    const r = await this.doc.send(new GetCommand({ TableName: this.table, Key: { pk: `COUNT#${key}`, sk: 'META' }, ConsistentRead: true }));
    const item = r.Item as { n?: number; ttl?: number } | undefined;
    return item && (!item.ttl || item.ttl > Date.now() / 1000) ? item.n ?? 0 : 0;
  }

  async increment(key: string, windowSeconds: number): Promise<number> {
    const now = Math.floor(Date.now() / 1000);
    const r = await this.doc.send(new UpdateCommand({
      TableName: this.table, Key: { pk: `COUNT#${key}`, sk: 'META' },
      // A new window starts when the previous one expired.
      UpdateExpression: 'SET n = if_not_exists(n, :zero) + :one, #ttl = if_not_exists(#ttl, :ttl)',
      ConditionExpression: 'attribute_not_exists(#ttl) OR #ttl > :now',
      ExpressionAttributeNames: { '#ttl': 'ttl' },
      ExpressionAttributeValues: { ':zero': 0, ':one': 1, ':ttl': now + windowSeconds, ':now': now },
      ReturnValues: 'UPDATED_NEW',
    })).catch(async (e: Error) => {
      if (e.name !== 'ConditionalCheckFailedException') throw e;
      await this.put({ pk: `COUNT#${key}`, sk: 'META', n: 1, ttl: now + windowSeconds });
      return { Attributes: { n: 1 } };
    });
    return Number(r.Attributes?.n ?? 1);
  }

  async resetCount(key: string) { await this.doc.send(new DeleteCommand({ TableName: this.table, Key: { pk: `COUNT#${key}`, sk: 'META' } })); }

  // ---- audit trail

  async audit(realm: string, event: string, data: Record<string, unknown>, retentionDays = 365) {
    const at = nowIso();
    await this.put({ pk: `REALM#${realm}`, sk: `AUDIT#${at}#${Math.random().toString(36).slice(2, 8)}`, ttl: ttlIn(retentionDays * 86400), data: { at, event, ...data } });
  }

  async auditTrail(realm: string, limit = 100): Promise<Record<string, unknown>[]> {
    const r = await this.doc.send(new QueryCommand({
      TableName: this.table, KeyConditionExpression: 'pk = :p AND begins_with(sk, :s)', ExpressionAttributeValues: { ':p': `REALM#${realm}`, ':s': 'AUDIT#' },
      ScanIndexForward: false, Limit: limit,
    }));
    return (r.Items ?? []).map((i) => i.data as Record<string, unknown>);
  }

  async usersOf(realm: string): Promise<UserRecord[]> {
    const out: UserRecord[] = [];
    let start: Record<string, unknown> | undefined;
    do {
      const r = await this.doc.send(new QueryCommand({
        TableName: this.table, KeyConditionExpression: 'pk = :p AND begins_with(sk, :s)', ExpressionAttributeValues: { ':p': `REALM#${realm}`, ':s': 'USER#' },
        ExclusiveStartKey: start,
      }));
      out.push(...(r.Items ?? []).map((i) => i.data as UserRecord));
      start = r.LastEvaluatedKey;
    } while (start);
    return out;
  }

  // ---- OIDC models (oidc-provider adapter)

  async oidcGet(model: string, id: string) {
    const r = await this.doc.send(new GetCommand({ TableName: this.table, Key: { pk: `OIDC#${model}#${id}`, sk: 'META' }, ConsistentRead: true }));
    const item = r.Item as { data?: Record<string, unknown>; ttl?: number } | undefined;
    if (!item || (item.ttl && item.ttl < Date.now() / 1000)) return undefined;
    return item.data;
  }

  async oidcPut(model: string, id: string, payload: Record<string, unknown>, expiresIn: number | undefined, index: { grantId?: string; uid?: string; userCode?: string; account?: string }) {
    const ttl = expiresIn ? { ttl: ttlIn(expiresIn) } : {};
    await this.put({
      pk: `OIDC#${model}#${id}`, sk: 'META', data: payload, ...ttl,
      ...(index.grantId ? { gsi1pk: `GRANT#${index.grantId}`, gsi1sk: `OIDC#${model}#${id}` } : {}),
      ...(index.account ? { gsi3pk: `ACCOUNT#${index.account}`, gsi3sk: `OIDC#${model}#${id}` } : {}),
    });
    // Lookups by uid/user code must be strongly consistent (a session is read right after it is written), so they
    // use pointer items instead of an eventually consistent index.
    if (index.uid) await this.put({ pk: `OIDCREF#UID#${index.uid}`, sk: 'META', ref: `${model}#${id}`, ...ttl });
    if (index.userCode) await this.put({ pk: `OIDCREF#USERCODE#${index.userCode}`, sk: 'META', ref: `${model}#${id}`, ...ttl });
  }

  async oidcByRef(kind: 'UID' | 'USERCODE', key: string) {
    const r = await this.doc.send(new GetCommand({ TableName: this.table, Key: { pk: `OIDCREF#${kind}#${key}`, sk: 'META' }, ConsistentRead: true }));
    const ref = r.Item?.ref as string | undefined;
    if (!ref || (r.Item?.ttl && r.Item.ttl < Date.now() / 1000)) return undefined;
    const [model, ...rest] = ref.split('#');
    return this.oidcGet(model!, rest.join('#'));
  }

  async oidcConsume(model: string, id: string) {
    await this.doc.send(new UpdateCommand({
      TableName: this.table, Key: { pk: `OIDC#${model}#${id}`, sk: 'META' }, UpdateExpression: 'SET #d.#c = :c',
      ConditionExpression: 'attribute_exists(pk)', ExpressionAttributeNames: { '#d': 'data', '#c': 'consumed' }, ExpressionAttributeValues: { ':c': Math.floor(Date.now() / 1000) },
    })).catch((e: Error) => { if (e.name !== 'ConditionalCheckFailedException') throw e; });
  }

  async oidcDelete(model: string, id: string) {
    const current = await this.oidcGet(model, id);
    await this.doc.send(new DeleteCommand({ TableName: this.table, Key: { pk: `OIDC#${model}#${id}`, sk: 'META' } }));
    for (const [kind, key] of [['UID', current?.uid], ['USERCODE', current?.userCode]] as const) {
      if (typeof key === 'string') await this.doc.send(new DeleteCommand({ TableName: this.table, Key: { pk: `OIDCREF#${kind}#${key}`, sk: 'META' } }));
    }
  }

  /** Deletes every item of an index partition (tokens of a grant, sessions and grants of an account). */
  async deleteByIndex(index: 'gsi1' | 'gsi3', key: string) {
    const attr = index === 'gsi1' ? 'gsi1pk' : 'gsi3pk';
    let start: Record<string, unknown> | undefined;
    do {
      const r = await this.doc.send(new QueryCommand({
        TableName: this.table, IndexName: index, KeyConditionExpression: `${attr} = :k`, ExpressionAttributeValues: { ':k': key },
        ProjectionExpression: 'pk, sk', ExclusiveStartKey: start,
      }));
      const keys = (r.Items ?? []).map((i) => ({ pk: i.pk, sk: i.sk }));
      for (let i = 0; i < keys.length; i += 25) {
        await this.doc.send(new BatchWriteCommand({ RequestItems: { [this.table]: keys.slice(i, i + 25).map((Key) => ({ DeleteRequest: { Key } })) } }));
      }
      start = r.LastEvaluatedKey;
    } while (start);
  }
}
