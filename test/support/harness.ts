import { execSync } from 'node:child_process';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { CreateTableCommand, DeleteTableCommand, DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { admin, newRuntimeSecret, type AdminEvent } from '../../runtime/admin.js';
import { createApp } from '../../runtime/app.js';
import { Cipher } from '../../runtime/crypto.js';
import type { Deps, RuntimeSecret } from '../../runtime/deps.js';
import { HookCaller } from '../../runtime/hooks.js';
import { MemoryMailer } from '../../runtime/mail.js';
import { Store } from '../../runtime/store.js';

export const DYNAMO_PORT = 8011;
const CONTAINER = 'cdk-serverless-idp-test-dynamo';

/** DynamoDB Local in Docker (started once per test run, in memory). */
export function startDynamo() {
  const running = execSync(`docker ps -q -f name=${CONTAINER}`).toString().trim();
  if (!running) {
    execSync(`docker run --rm -d --name ${CONTAINER} -p ${DYNAMO_PORT}:8000 amazon/dynamodb-local:latest -jar DynamoDBLocal.jar -inMemory`, { stdio: 'ignore' });
  }
}

export const dynamoClient = () => new DynamoDBClient({ endpoint: `http://localhost:${DYNAMO_PORT}`, region: 'us-east-1', credentials: { accessKeyId: 'x', secretAccessKey: 'x' } });

/** Same schema as the construct: pk/sk, two GSIs and TTL. */
export async function createTable(client: DynamoDBClient, name: string) {
  for (let i = 0; i < 40; i++) {
    try {
      await client.send(new DeleteTableCommand({ TableName: name })).catch(() => undefined);
      const s = { AttributeType: 'S' as const };
      await client.send(new CreateTableCommand({
        TableName: name, BillingMode: 'PAY_PER_REQUEST',
        AttributeDefinitions: ['pk', 'sk', 'gsi1pk', 'gsi1sk', 'gsi3pk', 'gsi3sk'].map((AttributeName) => ({ AttributeName, ...s })),
        KeySchema: [{ AttributeName: 'pk', KeyType: 'HASH' }, { AttributeName: 'sk', KeyType: 'RANGE' }],
        GlobalSecondaryIndexes: [
          { IndexName: 'gsi1', KeySchema: [{ AttributeName: 'gsi1pk', KeyType: 'HASH' }, { AttributeName: 'gsi1sk', KeyType: 'RANGE' }], Projection: { ProjectionType: 'ALL' } },
          { IndexName: 'gsi3', KeySchema: [{ AttributeName: 'gsi3pk', KeyType: 'HASH' }, { AttributeName: 'gsi3sk', KeyType: 'RANGE' }], Projection: { ProjectionType: 'KEYS_ONLY' } },
        ],
      }));
      return;
    } catch (e) {
      if (i === 39) throw e;
      await new Promise((r) => setTimeout(r, 500)); // container still starting
    }
  }
}

export interface Harness {
  base: string; store: Store; mailer: MemoryMailer; secret: RuntimeSecret; deps: Deps; server: Server;
  admin(e: AdminEvent): Promise<Record<string, any>>; // eslint-disable-line @typescript-eslint/no-explicit-any
  close(): Promise<void>;
}

export async function startIdp(table: string): Promise<Harness> {
  const client = dynamoClient();
  await createTable(client, table);
  const store = new Store(table, client);
  const secret = newRuntimeSecret();
  const cipher = new Cipher(Buffer.from(secret.dataKey, 'base64'));
  const mailer = new MemoryMailer();
  const server = createServer();
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const settings = { tableName: table, secretId: 'test', issuerBase: base, productName: 'Test', auditRetentionDays: 30, realmCacheMs: 0 };
  const deps: Deps = { settings, secret, store, cipher, mailer, hooks: new HookCaller(cipher, fetch), fetch, now: () => new Date() };
  const app = createApp(deps);
  server.on('request', app.callback());
  return {
    base, store, mailer, secret, deps, server,
    admin: (e) => admin(e, { ...deps, secretIo: { read: async () => secret, write: async () => undefined } }) as never,
    close: () => new Promise<void>((r) => server.close(() => r())),
  };
}

/** Minimal browser: cookie jar (name + path, like a real browser) and manual redirects. */
export class Browser {
  cookies = new Map<string, { name: string; value: string; path: string }>();
  get jar() { return new Map([...this.cookies.values()].map((c) => [c.name, c.value])); }

  private remember(res: Response, url: string) {
    for (const c of res.headers.getSetCookie()) {
      const [pair, ...attrs] = c.split(';');
      const i = pair!.indexOf('=');
      const name = pair!.slice(0, i).trim();
      const value = pair!.slice(i + 1).trim();
      const path = attrs.map((a) => a.trim()).find((a) => /^path=/i.test(a))?.slice(5) || new URL(url).pathname.replace(/\/[^/]*$/, '') || '/';
      const key = `${name}|${path}`;
      if (!value || /expires=Thu, 01 Jan 1970/i.test(c)) this.cookies.delete(key);
      else this.cookies.set(key, { name, value, path });
    }
  }

  async fetch(url: string, init: RequestInit = {}) {
    const headers = new Headers(init.headers);
    const pathname = new URL(url).pathname;
    const sending = [...this.cookies.values()].filter((c) => pathname === c.path || pathname.startsWith(c.path.endsWith('/') ? c.path : `${c.path}/`) || c.path === '/');
    if (sending.length) headers.set('cookie', sending.map((c) => `${c.name}=${c.value}`).join('; '));
    const res = await fetch(url, { ...init, headers, redirect: 'manual' });
    this.remember(res, url);
    return res;
  }

  /** Follows redirects inside `origin`; stops at the first page or at a redirect elsewhere. */
  async follow(url: string, origin: string, init: RequestInit = {}): Promise<{ res: Response; url: string; html: string }> {
    let res = await this.fetch(url, init);
    let current = url;
    for (let i = 0; i < 15 && res.status >= 300 && res.status < 400; i++) {
      const next = new URL(res.headers.get('location')!, current).toString();
      if (!next.startsWith(origin)) return { res, url: next, html: '' };
      current = next;
      res = await this.fetch(next);
    }
    return { res, url: current, html: await res.text() };
  }

  async post(url: string, form: Record<string, string>, origin: string) {
    return this.follow(url, origin, { method: 'POST', body: new URLSearchParams(form), headers: { 'content-type': 'application/x-www-form-urlencoded' } });
  }
}

export const field = (html: string, name: string) => new RegExp(`name="${name}" value="([^"]*)"`).exec(html)?.[1] ?? '';
export const formAction = (html: string) => (/<form method="post" action="([^"]+)"/.exec(html)?.[1] ?? '').replace(/&amp;/g, '&');
