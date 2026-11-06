#!/usr/bin/env bash
# Brings up the compose stack, checks duo_client's TLS to frict-server from
# the Authentik server and worker, runs the e2e tests against it, saves all
# container logs, and tears the stack down. The LDAP outpost and SSSD
# containers are started by the tests once Authentik is provisioned.
#   EVIDENCE_DIR            where logs go (default: e2e/logs)
#   FRICT_E2E_ANSWER_DELAY  how long the fake phone takes to answer in the
#                           slow-human tests (default: 60s)
#   FRICT_CHALLENGE_TTL     frict-server's push expiry (default: 90s)
#   E2E_RUN                 go test -run filter (default: all)
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
evidence="${EVIDENCE_DIR:-$here/logs}"
export FRICT_E2E_ANSWER_DELAY="${FRICT_E2E_ANSWER_DELAY:-60s}"
export FRICT_CHALLENGE_TTL="${FRICT_CHALLENGE_TTL:-90s}"
mkdir -p "$evidence"
compose() { docker compose -f "$here/compose.yaml" "$@"; }

collect() {
  compose ps -a > "$evidence/compose-ps.txt" 2>&1 || echo "compose ps failed" >&2
  for svc in server worker frict-server frict-tls postgresql ldap sssd-default sssd-tuned; do
    compose logs --no-color --timestamps "$svc" > "$evidence/$svc.log" 2>&1 || echo "logs for $svc failed" >&2
  done
  compose down -v --remove-orphans
}
trap collect EXIT

"$here/gen-secrets.sh"
compose build
compose up --detach --wait --wait-timeout 600 postgresql server worker frict-server frict-tls

for svc in server worker; do
  "$here/../scripts/duo-tls-check.sh" "$(compose ps -q "$svc")" "https://frict.frict.test" \
    | tee "$evidence/duo-tls-check-$svc.log"
done

cd "$here/.."
FRICT_E2E_SECRETS_DIR="$here/secrets" \
FRICT_E2E_COMPOSE_FILE="$here/compose.yaml" \
FRICT_E2E_AUTHENTIK_URL="http://127.0.0.1:9000" \
FRICT_E2E_FRICT_ADDR="127.0.0.1:8443" \
  go test -tags e2e -count=1 -v -timeout 20m -run "${E2E_RUN:-.}" ./e2e/ 2>&1 | tee "$evidence/go-test.log"
