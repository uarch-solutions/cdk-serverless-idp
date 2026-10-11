import type { ClientRecord, Realm, Store } from './store.js';

/**
 * Realms and applications kept in memory for the life of a warm Lambda. Every change made through the admin API bumps
 * one version item; the web function checks it at most every `checkEveryMs` (one eventually consistent read of a tiny
 * item) and drops its copies when it moved, so a change applies within that time without reading the realm and the
 * application on every request. Misses are never cached: a realm or an application created a moment ago is read
 * straight away. `checkEveryMs <= 0` turns the cache off (tests).
 */
export class ConfigCache {
  private readonly realms = new Map<string, Realm>();
  private readonly clients = new Map<string, ClientRecord>();
  private version: number | undefined;
  private checkedAt = -Infinity;

  constructor(private readonly store: Store, private readonly checkEveryMs: number, private readonly now = () => Date.now()) {}

  private drop() {
    this.realms.clear();
    this.clients.clear();
  }

  private async fresh() {
    if (this.checkEveryMs <= 0) return this.drop();
    if (this.now() - this.checkedAt < this.checkEveryMs) return;
    this.checkedAt = this.now();
    const version = await this.store.configVersion();
    if (version !== this.version) {
      this.drop();
      this.version = version;
    }
  }

  async realm(id: string): Promise<Realm | null> {
    await this.fresh();
    const hit = this.realms.get(id);
    if (hit) return hit;
    const realm = await this.store.realm(id);
    if (realm) this.realms.set(id, realm);
    return realm;
  }

  /** The copy in memory, without reading (error pages keep the realm's language and colors). */
  peek(id: string): Realm | null {
    return this.realms.get(id) ?? null;
  }

  /** `reload`: the copy may be older than the request (e.g. a redirect URI added a moment ago): read it again. */
  async client(id: string, opts: { reload?: boolean } = {}): Promise<ClientRecord | null> {
    await this.fresh();
    const hit = this.clients.get(id);
    if (hit && !opts.reload) return hit;
    const client = await this.store.client(id);
    if (client) this.clients.set(id, client);
    else this.clients.delete(id);
    return client;
  }
}
