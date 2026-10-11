# OpenID conformance

This folder runs the [OpenID Foundation conformance suite](https://gitlab.com/openid/conformance-suite) (the same
suite used for "OpenID Certified") against this provider, on your machine or in CI, with one command:

```bash
npm ci
./conformance/run.sh
```

It needs Docker and Node.js 24. Everything else runs in containers, and the script removes them at the end.

## What runs

| Container | What it is |
|---|---|
| `idp` | This provider, from this checkout ([`server.mts`](server.mts)): the same runtime as the Lambda, over HTTPS (self-signed) at `https://idp:3443`, on DynamoDB Local. |
| `dynamodb` | DynamoDB Local (in memory). |
| `server`, `nginx`, `mongodb` | The conformance suite: a Java (Spring) application that acts as the client application, runs the tests and checks every answer against the specification. Prebuilt images, release pinned in `run.sh` (`SUITE_TAG`). |
| `runner` | Python with the suite's `run-test-plan.py`, which creates the test plans, drives the suite and prints the results. |

`server.mts` seeds one realm (`conformance`), three confidential applications registered for the suite and one person,
and writes the suite configuration to `out/config.json`. The configuration also tells the suite's scripted browser how
to fill in the sign-in page, and takes the screenshots the suite asks for (a second sign-in, an error page), so the run
needs nobody.

## Plans

| Plan | Variant |
|---|---|
| `oidcc-basic-certification-test-plan` (Basic OP) | discovery, static clients, `client_secret_basic` |
| `oidcc-config-certification-test-plan` (Config OP) | discovery |

The Basic OP profile sends no PKCE, so the three test applications (one of them with `client_secret_post`) are
registered with `requirePkce: false`. Every other
application keeps PKCE mandatory (the default), and a public application can never turn it off.

## Latest result

Suite `release-v5.3.2`, Basic OP (34 modules) and Config OP: **0 failures** in 1,743 checked conditions.

| Result | Modules | Why |
|---|---|---|
| Passed | 23 | |
| Review | 4 | The suite asks a person to look at a screenshot (second sign-in after `prompt=login` and `max_age`, error pages); the run takes the screenshots. |
| Expected warning | 4 | "Should" items, each explained in [`expected-failures.json`](expected-failures.json): the e-mail address goes in the ID token on purpose; a person has only `name` in the profile scope; no `acr` values are defined. |
| Expected skip | 4 | Scopes `address` and `phone` (no such claims) and request objects (not supported, which the specification allows). |

Not run: `oidcc-ensure-post-request-succeeds`. The authorization endpoint accepts GET only, as `oidc-provider` does by
default: POST would need a `SameSite=None` session cookie, weaker against cross-site requests.

## Results

`run.sh` exits with an error when a test fails beyond [`expected-failures.json`](expected-failures.json) (each entry
says why it is expected). The results are exported to `out/*.zip` (one HTML log per test); the CI workflow
(`.github/workflows/conformance.yml`) keeps them as an artifact.

To look at a run in the suite's web interface, keep the containers up (`docker compose up -d` in this folder, then
`docker compose run --rm runner ...` as in `run.sh`) and open https://localhost.emobix.co.uk:8443 (it resolves to
127.0.0.1; accept the self-signed certificate).
