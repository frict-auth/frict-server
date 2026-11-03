"""Print sig v5 request vectors produced by the real duo_client library as JSON.

Run inside the pinned Authentik image so the vectors come from the exact
duo_client version Authentik ships:

    docker run --rm -i --entrypoint /ak-root/.venv/bin/python \
        ghcr.io/goauthentik/server:2026.8.5 -I - < scripts/gen_duo_vectors.py \
        > internal/duosig/testdata/duo_client_vectors.json
"""

import email.utils
import json
import sys

import duo_client
from duo_client.auth import Auth

IKEY = "DIXXXXXXXXXXXXXXXXXX"
SKEY = "test-secret-not-used-anywhere-real-0123456789"
HOST = "Duo.Frict.Test"
# Wed, 04 Nov 2026 12:00:00 UTC
FIXED_UNIX = 1793793600

_formatdate = email.utils.formatdate
email.utils.formatdate = lambda: _formatdate(FIXED_UNIX)

captured = []


class CapturingAuth(Auth):
    def _make_request(self, method, uri, body, headers):
        captured.append(
            {
                "method": method,
                "uri": uri,
                "body": body if body is not None else "",
                "headers": {k.decode(): v.decode() for k, v in headers.items()},
            }
        )
        raise _Captured()


class _Captured(Exception):
    pass


def capture(name, call):
    try:
        call()
    except _Captured:
        pass
    captured[-1]["name"] = name


client = CapturingAuth(IKEY, SKEY, HOST, user_agent="authentik@test")

capture("enroll", lambda: client.enroll("alice"))
capture("enroll_status", lambda: client.enroll_status("DU123", "act-code"))
capture(
    "auth_authentik_params",
    lambda: client.auth(
        "auto",
        user_id="DU123",
        ipaddr="203.0.113.7",
        type="authentik Login request",
        display_username="élodie",
        device="auto",
        pushinfo="Domain=localhost%3A9000&Application=Gr%C3%A4fana",
    ),
)
capture(
    "get_with_query_params",
    lambda: client.api_call(
        "GET",
        "/auth/v2/auth_status",
        {"txid": "a b/c~d", "Zeta": ["2", "1"], "ünï": "x+y=z&"},
    ),
)
capture(
    "post_with_x_duo_header",
    lambda: client.api_call(
        "POST",
        "/auth/v2/auth",
        {"factor": "auto"},
        additional_headers={"X-Duo-Test-Header": "v", "x-duo-another": "w"},
    ),
)

json.dump(
    {
        "duo_client_version": duo_client.client.__version__,
        "ikey": IKEY,
        "skey": SKEY,
        "host": HOST,
        "unix_time": FIXED_UNIX,
        "vectors": captured,
    },
    sys.stdout,
    indent=2,
    sort_keys=True,
    ensure_ascii=False,
)
sys.stdout.write("\n")
