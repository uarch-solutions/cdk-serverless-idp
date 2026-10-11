# Security

## Reporting a vulnerability

Please report security issues privately through
[GitHub Security Advisories](https://github.com/uarch-solutions/cdk-serverless-idp/security/advisories/new). Do not open
a public issue. We answer within 5 business days.

## Threat model

| Threat | Mitigation |
|---|---|
| **Authorization code interception** | PKCE (S256) is mandatory for every client. Codes are single use and expire in 60 s. Redirect URIs must match exactly. |
| **Stolen refresh token** | Rotation on every use. Reusing a consumed refresh token revokes the whole grant (every token of that sign-in). |
| **Token forgery** | ES256 signatures. Private keys live only in Secrets Manager and are readable only by the provider's functions. Rotation keeps the previous key published until its tokens expire. |
| **Password guessing** | argon2id (64 MiB, t=3). Per e-mail and per IP failure limits with a lockout window. Unknown e-mails cost the same as wrong passwords. |
| **Account enumeration** | Same message and timing for wrong password, unknown e-mail and disabled account. Password reset always gives the same answer. |
| **Second factor bypass or replay** | TOTP with ±30 s of drift. A code is never accepted twice (last used step). Recovery codes are single use and stored as hashes. Social logins also go through the second factor. |
| **CSRF** | Double-submit token (`SameSite=Strict` cookie) on every form. Interaction cookies are signed and bound to the interaction. |
| **XSS and clickjacking** | Hosted pages have no JavaScript: `default-src 'none'` (no `script-src`), `frame-ancestors 'none'`, and every value is HTML-escaped. |
| **Bypassing CloudFront** | The Function URL refuses requests without the origin secret header that only CloudFront adds. |
| **Cross-tenant access** | Each realm is a separate issuer with its own cookies. An application must be allowed in the realm, tokens carry the realm, and people, sessions and social identities are keyed by realm. |
| **Malicious or broken application hook** | Only claims with the application's prefix are kept, reserved claims (`sub`, `aud`, `iss`, `realm`…) can never be overwritten, and the size is capped at 4 KB. On failure the sign-in is denied by default. |
| **Admin API abuse** | No public route: only IAM principals with `lambda:InvokeFunction` on the admin function. |
| **Sensitive data at rest** | TOTP secrets, client secrets and upstream secrets are encrypted with AES-256-GCM (data key in Secrets Manager). Single-use links (invite and reset) are stored as SHA-256 hashes. DynamoDB is encrypted at rest. |
| **Lost sessions after compromise** | A new password, a disabled account or the admin `revokeSessions` action ends every session and grant of the person. |

## Not in scope (yet)

- WebAuthn and passkeys.
- Breached-password checks.
- Risk-based authentication.
- Running the OpenID Foundation conformance suite in CI. Until then, the end-to-end tests cover the code flow, PKCE,
  rotation, reuse detection and realm isolation.
