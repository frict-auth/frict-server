"""Checks that duo_client, as Authentik calls it, completes a TLS handshake.

Runs inside an Authentik server or worker container, with that container's
duo_client and its ca_certs.pem, so it sees whatever bundle is mounted there:

    docker exec -i <container> python - https://<duo-api-host> < scripts/duo_tls_check.py

Authentik constructs duo_client.Auth without ca_certs, so the bundle used is
duo_client's DEFAULT_CA_CERTS; this does the same. Any HTTP response counts as
a pass: the dummy credentials make the status meaningless. Exit codes:
0 handshake ok, 1 TLS failure, 2 any other failure (DNS, connect, timeout).
"""

import hashlib
import ssl
import sys
import traceback
from importlib.metadata import version
from urllib.parse import urlsplit

import duo_client
from duo_client.client import DEFAULT_CA_CERTS


def main(url: str) -> int:
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.hostname or parts.port not in (None, 443):
        print(f"usage: duo_tls_check.py https://<host>  (got {url!r}; duo_client only speaks https on 443)")
        return 2
    host = parts.hostname

    print(f"duo_client {version('duo_client')}  {ssl.OPENSSL_VERSION}")
    try:
        with open(DEFAULT_CA_CERTS, "rb") as f:
            bundle = f.read()
    except OSError as e:
        print(f"FAIL other: cannot read duo_client ca_certs {DEFAULT_CA_CERTS}: {e}")
        return 2
    print(f"ca_certs {DEFAULT_CA_CERTS}  roots={bundle.count(b'BEGIN CERTIFICATE')}  sha256={hashlib.sha256(bundle).hexdigest()}")
    print(f"host {host}")

    client = duo_client.Auth("DIXXXXXXXXXXXXXXXXXX", "x" * 40, host, timeout=15)
    # Not ping(): it raises on a non-JSON 404, and only the handshake is under test.
    try:
        response, _ = client.api_call("GET", "/auth/v2/ping", {})
    except ssl.SSLError as e:
        traceback.print_exc(file=sys.stdout)
        print(f"FAIL tls: {e}")
        return 1
    except Exception as e:
        traceback.print_exc(file=sys.stdout)
        print(f"FAIL other: {type(e).__name__}: {e}")
        return 2
    print(f"PASS handshake ok, HTTP {response.status} {response.reason}")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: duo_tls_check.py https://<host>")
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
