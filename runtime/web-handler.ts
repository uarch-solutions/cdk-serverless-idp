import serverless from 'serverless-http';
import { createApp } from './app.js';
import { depsFromEnv } from './deps.js';

let web: ReturnType<typeof serverless> | undefined;

/** Public Lambda (Function URL behind CloudFront): hosted pages and the OpenID Provider of every realm. */
export const webHandler = async (event: unknown, context: unknown) => {
  web ??= serverless(createApp(await depsFromEnv()));
  return web(event as never, context as never);
};
