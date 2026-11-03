#!/usr/bin/env bash
# Brings up the M0 compose stack, runs the e2e tests against it, saves all
# container logs, and tears the stack down.
#   EVIDENCE_DIR           where logs go (default: e2e/logs)
#   FRICT_STUB_AUTH_DELAY  how long the stub blocks /auth (default: 60s)
#   E2E_RUN                go test -run filter (default: all)
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
evidence="${EVIDENCE_DIR:-$here/logs}"
export FRICT_STUB_AUTH_DELAY="${FRICT_STUB_AUTH_DELAY:-60s}"
mkdir -p "$evidence"
compose() { docker compose -f "$here/compose.yaml" "$@"; }

collect() {
  compose ps -a > "$evidence/compose-ps.txt" 2>&1 || echo "compose ps failed" >&2
  for svc in server worker duo-stub postgresql; do
    compose logs --no-color --timestamps "$svc" > "$evidence/$svc.log" 2>&1 || echo "logs for $svc failed" >&2
  done
  compose down -v --remove-orphans
}
trap collect EXIT

"$here/gen-secrets.sh"
compose up --build --detach --wait --wait-timeout 600

cd "$here/.."
FRICT_E2E_SECRETS_DIR="$here/secrets" \
FRICT_E2E_AUTHENTIK_URL="http://127.0.0.1:9000" \
  go test -tags e2e -count=1 -v -timeout 20m -run "${E2E_RUN:-.}" ./e2e/ 2>&1 | tee "$evidence/go-test.log"
