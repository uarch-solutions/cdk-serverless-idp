# Contributing

Issues and pull requests are welcome. Security issues: see [SECURITY.md](SECURITY.md).

```bash
npm ci
npm run build   # construct (tsc) + Lambda bundles (esbuild) in dist/
npm test        # unit, construct and end-to-end tests (starts DynamoDB Local in Docker)
```

- The runtime lives in `runtime/` (TypeScript, bundled with esbuild); the construct in `src/`.
- Every behaviour change needs a test. Sign-in flows are tested end to end in `test/flow.test.ts` with a real
  `oidc-provider`, DynamoDB Local and a fake browser.
- Never weaken a default (PKCE, CSRF, CSP, rate limits) without discussing it in an issue first.
- Describe the user-visible change in `CHANGELOG.md`.
