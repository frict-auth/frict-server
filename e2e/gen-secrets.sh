#!/usr/bin/env bash
# Generates throwaway credentials and a test CA for one e2e run into e2e/secrets/.
# Files are world-readable so containers running as other uids can read them;
# nothing here is used outside the local compose stack.
set -euo pipefail

dir="$(cd "$(dirname "$0")" && pwd)/secrets"
rm -rf "$dir"
mkdir -p "$dir"
cd "$dir"

openssl ecparam -name prime256v1 -genkey -noout -out ca.key
openssl req -x509 -new -key ca.key -sha256 -days 2 -subj "/CN=Frict M0 throwaway test CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -out ca.pem

# leaf NAME HOSTNAME: NAME.pem / NAME.key signed by the test CA for HOSTNAME.
leaf() {
  openssl ecparam -name prime256v1 -genkey -noout -out "$1.key"
  openssl req -new -key "$1.key" -subj "/CN=$2" -out "$1.csr"
  openssl x509 -req -in "$1.csr" -CA ca.pem -CAkey ca.key -CAcreateserial -sha256 -days 2 \
    -extfile <(printf '%s\n' \
      "subjectAltName=DNS:$2" \
      "basicConstraints=critical,CA:FALSE" \
      "keyUsage=critical,digitalSignature" \
      "extendedKeyUsage=serverAuth") \
    -out "$1.pem"
  rm "$1.csr"
}
leaf frict frict.frict.test
leaf ldap ldap.frict.test
rm ca.key ca.srl

rand() { openssl rand -hex "$1"; }
rand 20 > duo-client-secret
rand 24 > akadmin-password
rand 24 > akadmin-token
rand 24 > ldap-svc-password
pg_pass="$(rand 24)"
cat > authentik.env <<ENV
POSTGRES_PASSWORD=$pg_pass
AUTHENTIK_POSTGRESQL__PASSWORD=$pg_pass
AUTHENTIK_SECRET_KEY=$(rand 32)
AUTHENTIK_BOOTSTRAP_PASSWORD=$(cat akadmin-password)
AUTHENTIK_BOOTSTRAP_TOKEN=$(cat akadmin-token)
AUTHENTIK_BOOTSTRAP_EMAIL=akadmin@frict.test
ENV
chmod 0644 ./*
