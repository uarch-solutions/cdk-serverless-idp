# Changelog

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
