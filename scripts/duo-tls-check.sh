#!/usr/bin/env bash
# Usage: scripts/duo-tls-check.sh CONTAINER https://<duo-api-host>
# Runs duo_tls_check.py inside a running Authentik container. Exits non-zero
# unless duo_client, with the container's ca_certs.pem, completes a TLS
# handshake with the host. Run it against the server and the worker.
set -euo pipefail
if [ $# -ne 2 ]; then
  echo "usage: $0 CONTAINER https://<duo-api-host>" >&2
  exit 2
fi
docker exec -i "$1" python - "$2" < "$(dirname "$0")/duo_tls_check.py"
