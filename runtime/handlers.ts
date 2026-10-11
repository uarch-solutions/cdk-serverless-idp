import serverless from 'serverless-http';
import { admin, type AdminEvent } from './admin.js';
import { Cipher } from './crypto.js';
import { depsFromEnv, readSecret, settingsFromEnv, writeSecret } from './deps.js';
import { HookCaller } from './hooks.js';
import { SesMailer } from './mail.js';
import { createApp } from './app.js';
import { Store } from './store.js';

let web: ReturnType<typeof serverless> | undefined;

/** Public Lambda (Function URL behind CloudFront): hosted pages and the OpenID Provider of every realm. */
export const webHandler = async (event: unknown, context: unknown) => {
  web ??= serverless(createApp(await depsFromEnv()));
  return web(event as never, context as never);
};

/** Admin Lambda (IAM only). With no `action` (deployment trigger) it bootstraps the installation secret. */
export const adminHandler = async (event: Partial<AdminEvent> | undefined) => {
  const settings = settingsFromEnv();
  const secret = await readSecret(settings.secretId, 0);
  const cipher = secret ? new Cipher(Buffer.from(secret.dataKey, 'base64')) : null;
  return admin((event?.action ? event : { action: 'bootstrap' }) as AdminEvent, {
    settings, secret, cipher,
    store: new Store(settings.tableName),
    mailer: new SesMailer(settings.mailFrom),
    hooks: new HookCaller(cipher ?? new Cipher(Buffer.alloc(32)), fetch),
    fetch,
    now: () => new Date(),
    originVerify: process.env.ORIGIN_VERIFY || undefined,
    secretIo: { read: () => readSecret(settings.secretId, 0), write: (s) => writeSecret(settings.secretId, s) },
  });
};
