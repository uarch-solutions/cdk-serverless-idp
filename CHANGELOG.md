# Changelog

## 0.6.0

- Theme per realm (`theme`: `light`, `dark` or `auto`) for the hosted pages. `auto`, the default, keeps following the
  device as before; `light` or `dark` fixes it (e.g. a brand designed on light).

## 0.5.0

- Admin: `deleteRealm` removes a realm with everything in it (people and their e-mail pointers, sessions and grants,
  social identities, audit trail); `removeRedirectUris` takes a customer's addresses out of a shared application;
  `listRealms` lists the realm ids for housekeeping.

## 0.4.0

- Checked against the OpenID Foundation conformance suite (Basic OP and Config OP plans) in CI; `conformance/run.sh`
  runs it on any machine with Docker (see `conformance/README.md`).
- **Changed:** without `resource`, the access token is the standard one for the userinfo endpoint. An application that
  wants the ES256 JWT with its hook claims asks for `resource=urn:idp:app:<clientId>` in the authorization and token
  requests. Before, every access token was that JWT, which the userinfo endpoint refuses.
- RS256 ID tokens (OpenID Connect requires every provider to support them); ES256 stays the default. New installations
  get an RSA key; `bootstrap` (run on every deployment) adds one to existing installations; `rotateKeys` rotates both.
- Per application: `requirePkce: false` (confidential applications only) and `tokenEndpointAuthMethod:
  'client_secret_post'`.
- The `claims` request parameter is supported.

## 0.3.0

- Realms and applications stay in memory while the Lambda is warm. Every change through the admin API bumps one
  version item; the web function checks it at most every 30 s (`CONFIG_CHECK_MS`, one eventually consistent read of a
  tiny item) instead of reading the realm and the application on every request. A redirect URI or realm an application
  gained a moment ago is read again at once, so a new customer signs in right after it is created.
- `countUsers` counts with `Select: COUNT` instead of reading every person.

## 0.2.1

- Hook timeout up to 10 s (was 5 s): applications whose hook runs on a cold-starting function in a VPC need more than 3 s on the first call.

## 0.2.0

- Second factor required per person (`mfaRequired`), with a grace period (`mfaGraceUntil`) during which the enrollment can be postponed.
- Temporary passwords (`setPassword` with `temporary: true`, or `passwordChangeRequired`): a new password is chosen at the next sign-in.
- One social-login callback for every realm (`<url>/federated/callback/<provider>`): register a single redirect URI at Google and Facebook.
- Admin: pre-hashed argon2 passwords in `upsertUser` and `addRedirectUris`.

## 0.1.0

- First release: the `ServerlessIdp` construct. A multi-tenant OpenID Connect provider on Lambda and DynamoDB, with:
  - realms per customer and applications per SaaS;
  - post-login hooks (HTTPS with HMAC, or Lambda);
  - argon2id passwords;
  - TOTP and recovery codes;
  - Google and Facebook login;
  - password reset and invites;
  - an account console;
  - an IAM-only admin API with bulk import;
  - ES256 keys with rotation;
  - rate limits and an audit trail.
