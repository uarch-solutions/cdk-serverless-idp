// Bundles the two Lambda functions into dist/ (shipped in the npm package: consumers need no bundler).
import { build } from 'esbuild';
import { rmSync, writeFileSync } from 'node:fs';

rmSync('dist', { recursive: true, force: true });
for (const name of ['web', 'admin']) {
  const result = await build({
    entryPoints: [`runtime/entry/${name}.ts`],
    outfile: `dist/${name}/index.mjs`,
    bundle: true,
    platform: 'node',
    target: 'node22',
    format: 'esm',
    minify: true,
    // oidc-provider names storage models after its class names: minification must keep them.
    keepNames: true,
    sourcemap: false,
    legalComments: 'eof',
    // The AWS SDK v3 comes with the Lambda Node.js runtime.
    external: ['@aws-sdk/*'],
    banner: { js: "import { createRequire as __cr } from 'node:module'; const require = __cr(import.meta.url);" },
    metafile: true,
  });
  const bytes = Object.values(result.metafile.outputs).reduce((t, o) => t + o.bytes, 0);
  writeFileSync(`dist/${name}/package.json`, JSON.stringify({ type: 'module' }));
  console.log(`dist/${name}/index.mjs: ${(bytes / 1024).toFixed(0)} KiB`);
}
