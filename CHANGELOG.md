# Changelog

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
