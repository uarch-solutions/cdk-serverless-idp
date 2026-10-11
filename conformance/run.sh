#!/usr/bin/env bash
# OpenID Foundation conformance suite against this provider (TD-079): Basic OP and Config OP plans, static clients,
# discovery. Fails if any test fails beyond conformance/expected-*.json. Needs Docker and `npm ci` (the provider runs from
# this checkout); everything else runs in containers.
set -euo pipefail
cd "$(dirname "$0")"
export SUITE_TAG="${SUITE_TAG:-release-v5.3.2}" # conformance-suite release: prebuilt images and run-test-plan.py of the same version
mkdir -p out

[ -f out/idp.crt ] || openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 30 \
  -subj /CN=idp -addext subjectAltName=DNS:idp -keyout out/idp.key -out out/idp.crt 2>/dev/null
rm -f out/config.json

if [ ! -d suite ]; then
  git clone -q --depth 1 --branch "$SUITE_TAG" https://gitlab.com/openid/conformance-suite.git suite
fi

docker compose up -d
trap 'docker compose logs idp > out/idp.log 2>&1 || true; docker compose down -v' EXIT

echo "waiting for the provider and the suite..."
for i in $(seq 1 120); do
  [ -f out/config.json ] && curl -skf https://localhost.emobix.co.uk:8443/api/plan?length=1 >/dev/null && break
  [ -z "$(docker compose ps -q --status running idp)" ] && { docker compose logs idp; exit 1; }
  sleep 5
done
[ -f out/config.json ] || { docker compose logs idp; exit 1; }

# Basic OP plan, every module except oidcc-ensure-post-request-succeeds: oidc-provider keeps the authorization
# endpoint GET-only by default (POST needs the SameSite=None session cookie, weaker against CSRF), a deliberate choice.
BASIC=oidcc-server,oidcc-response-type-missing,oidcc-userinfo-get,oidcc-userinfo-post-header,oidcc-userinfo-post-body,oidcc-ensure-request-without-nonce-succeeds-for-code-flow,oidcc-scope-profile,oidcc-scope-email,oidcc-scope-address,oidcc-scope-phone,oidcc-scope-all,oidcc-alternate-happy-flow,oidcc-display-page,oidcc-display-popup,oidcc-prompt-login,oidcc-prompt-none-not-logged-in,oidcc-prompt-none-logged-in,oidcc-max-age-1,oidcc-max-age-10000,oidcc-ensure-request-with-unknown-parameter-succeeds,oidcc-id-token-hint,oidcc-login-hint,oidcc-ui-locales,oidcc-claims-locales,oidcc-ensure-request-with-acr-values-succeeds,oidcc-codereuse,oidcc-codereuse-30seconds,oidcc-ensure-registered-redirect-uri,oidcc-server-client-secret-post,oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported,oidcc-claims-essential,oidcc-ensure-request-object-with-redirect-uri,oidcc-refresh-token,oidcc-ensure-request-with-valid-pkce-succeeds

# The runner joins the suite's network (localhost.emobix.co.uk is nginx there).
docker compose run --rm -e BASIC="$BASIC" runner sh -c 'pip install -q --root-user-action=ignore -r suite/scripts/requirements.txt && python suite/scripts/run-test-plan.py \
  --expected-failures-file expected-failures.json --expected-skips-file expected-skips.json --export-dir out \
  "oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client]:$BASIC" out/config.json \
  oidcc-config-certification-test-plan out/config.json'
