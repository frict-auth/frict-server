# M0 findings

Feasibility spike results for PLAN.md §Milestones M0. Versions under test:
Authentik **2026.8.5** (`ghcr.io/goauthentik/server@sha256:602227a8…79a5`),
which bundles `duo_client` **5.6.1** and Python 3.14.

"Proven" means a test in this repo exercises it and was shown to fail when
the thing it checks is broken. "Inferred" means read from source, not
exercised.

| Item | Result | Basis |
|---|---|---|
| (a) sig v5 verification | **Pass** | Proven (unit + e2e) |
| (b) GTS chain passes `duo_client` pinning | Pending | Separate PR, real certificate |
| (c) blocking `/auth` survives ~60 s | **Pass** (60 s and 120 s) | Proven (e2e, measured) |
| (c′) upper limit on `/auth` blocking | ~215 s, then HTTP 408 | 240 s run measured; cause inferred from source |
| (d) push over an LDAP bind | Pending | Next PR |
| (e) SSSD/PAM timeout outlasts approval | Pending | Next PR |
| Login page can show a number | **No** | Inferred from source |

## How to reproduce

```sh
go test -race ./...          # unit (needs cgo/gcc)
e2e/run.sh                   # compose stack + e2e, FRICT_STUB_AUTH_DELAY=60s
```

`e2e/run.sh` generates a throwaway CA, stub certificate, Duo client secret
and Authentik bootstrap credentials into `e2e/secrets/` (git-ignored), mounts
the CA over `duo_client/ca_certs.pem` in the Authentik server and worker,
brings the stack up, runs `go test -tags e2e ./e2e/`, saves every container's
log to `$EVIDENCE_DIR` (default `e2e/logs/`), and tears the stack down.
`FRICT_STUB_AUTH_DELAY` sets how long the stub blocks `/auth`; `E2E_RUN`
filters tests.

Raw evidence from the runs behind this document is under
`/tmp/frict-m0-evidence/` on the agent VM (not committed). Directory names
below refer to it.

## Which endpoints Authentik calls

From Authentik 2026.8.5 source, the Duo stages call exactly:

- `POST /auth/v2/enroll` — `authentik/stages/authenticator_duo/stage.py:57`
- `POST /auth/v2/enroll_status` — `authentik/stages/authenticator_duo/stage.py:85`
  and `authentik/stages/authenticator_duo/api.py:105`
- `POST /auth/v2/auth` (synchronous, `async=0`) —
  `authentik/stages/authenticator_validate/challenge.py:276`

`Admin.get_users_iterator` (`/admin/v1/users`) is only reached by the
"import devices" admin action (`authentik/stages/authenticator_duo/api.py:189`)
and only when admin keys are configured; not implemented. `duo_client` itself
calls no endpoint on its own (no implicit ping/check), so `/auth/v2/ping` and
`/auth/v2/check` are not implemented; the stub answers them 404.

## (a) sig v5 verification — Pass, proven

**What was checked.** `internal/duosig` verifies requests the way
`duo_client` 5.6.1 signs them (`duo_client/client.py:111-182, 290-331`):
HMAC-SHA512 with the client secret over
`Date \n METHOD \n host \n path \n canon_params(query) \n sha512(body) \n sha512(X-Duo-* headers)`,
sent as `Authorization: Basic base64(client_id:hexsig)`. Requests with a
missing or malformed header, unknown client ID, missing/unparseable `Date`,
`Date` more than 5 minutes from now, repeated `X-Duo-*` header, or any
signature mismatch are rejected with 401 before the stub does any work.

**Evidence.**

- Fixtures `internal/duosig/testdata/duo_client_vectors.json` were produced
  by the real `duo_client` 5.6.1 inside the pinned Authentik image
  (`scripts/gen_duo_vectors.py`; command in its docstring). They cover
  Authentik's actual `enroll`, `enroll_status` and `auth` calls (including
  non-ASCII `display_username` and URL-encoded `pushinfo`), a GET with query
  parameters needing escaping, and a request with `X-Duo-*` headers.
- `TestVerifyAcceptsDuoClientVectors` accepts all of them;
  `TestSignRoundTripsThroughVerify` reproduces `duo_client`'s exact
  `Authorization` header for each; `TestVerifyRejects` covers 23 negative
  cases. Log: `unit/go-test-race.log`.
- End to end, `TestWrongClientSecretFailsLogin`: a Duo stage configured with
  a wrong client secret makes the stub reject `/auth` (stub log:
  `signature rejected path=/auth/v2/auth reason="signature mismatch"`),
  Authentik shows "Duo denied access", no session is created, and Authentik
  records a `configuration_error` event "Failed to DUO authenticate user:
  Received 401 Invalid signature in request credentials". The rejection
  returns in seconds, well under the 60 s push delay, so `/auth` never ran.
  Logs: `e2e-60s-baseline/`.

**Negative controls.**

- `Verify` short-circuited to `return nil` → unit tests fail
  (`mut-unit-verify-disabled/`).
- `X-Duo-*` headers left out of the canonical string → the `X-Duo` vector
  and two rejection cases fail (`mut-unit-xduo-hash-dropped/`).
- Signature check in the stub disabled → `TestWrongClientSecretFailsLogin`
  fails because the wrong-secret login succeeds (`mut-e2e-sigcheck-disabled/`).

Each directory holds the mutation as `mutation.diff` and the failing run.

## (c) blocking `/auth` survives ~60 s — Pass, proven

**What was checked.** `TestDuoPushSurvivesStubDelay` drives Authentik's
flow-executor API (no browser): identification → password → Duo setup stage
(enroll + enroll_status against the stub, over TLS with the test CA) →
`xak-flow-redirect`; then a fresh session: identification → password →
validate stage → submit the Duo device. The stub blocks `/auth` for
`FRICT_STUB_AUTH_DELAY` before approving. The test times that one POST,
requires it to take at least the delay and end in `xak-flow-redirect`, and
then requires `/api/v3/core/users/me/` on that session to return the user.

**Evidence.**

| Stub delay | Measured POST | Result | Log |
|---|---|---|---|
| 60 s | 1m0.559s | logged in | `e2e-60s-baseline/` |
| 120 s | 2m0.602s | logged in | `e2e-delay-120s/` |
| 240 s | ≈213 s (from log timestamps) | **HTTP 408** from Authentik, no login | `e2e-delay-240s/` |

The stub log shows each `/auth` held for the full delay
(`auth approved … after=1m0.04…s`).

**Negative control.** Stub changed to approve immediately →
`TestDuoPushSurvivesStubDelay` fails on the elapsed-time check
(`mut-e2e-stub-ignores-delay/`).

**Timeouts on the path (inferred from source, 2026.8.5).**

- `duo_client` uses `socket._GLOBAL_DEFAULT_TIMEOUT` unless given one
  (`duo_client/client.py:219, 250-253, 400`); Authentik passes none
  (`authentik/stages/authenticator_duo/models.py:41-48`) and never calls
  `socket.setdefaulttimeout`. The outbound call itself has no timeout.
- The Rust front server wraps every request in a `TimeoutLayer` of
  `timeout_http_read_header + timeout_http_read + timeout_http_write +
  timeout_http_idle` = 5 + 30 + 60 + 120 = **215 s** by default, answering
  408 (`packages/ak-axum/src/router.rs:36-47`, defaults in
  `authentik/lib/default.yml:167-170`). The `timeout_http_write: 60s` that
  looks like a 60 s ceiling applies to the Go outposts
  (`internal/utils/web/server.go:24`), not to the core server path.
- gunicorn `timeout = 30` (`lifecycle/gunicorn.conf.py:59`) does not cut
  the request: the 60 s and 120 s runs pass with Uvicorn workers.

**What happens past the limit (240 s run).** The executor POST failed with
HTTP 408 and an empty body (`e2e-delay-240s/go-test.log`). The stub logged
`auth blocking` at 17:16:30.98 and the test ended 220.02 s after it started
(user creation at 17:16:24.4), so the POST lasted about 213 s. That is
consistent with the 215 s `TimeoutLayer` (the timeout starts when the request
arrives, and the test clock starts slightly earlier). That run predates the
elapsed time added to the test's failure message, so the figure comes from log
timestamps, not from the test. Not determined: whether Authentik's Python side
keeps the `/auth` connection open after the 408. The stack was torn down
right after the failure, before the stub could log a disconnect.

Consequence for M1: Frict's own push expiry (PLAN: 60–120 s) is well inside
this limit; an expiry at or above ~210 s would turn into an opaque 408 for
the user. Raising the web `timeout_http_*` settings would raise the limit, but
Frict doesn't need that.

## Number matching — the login page cannot show a number (inferred)

Nothing the Duo server returns from `/auth` reaches the login page, and
structurally it could not arrive in time:

- The validate stage's per-device challenge for Duo is `{}`: only WebAuthn
  and email devices get challenge data
  (`authentik/stages/authenticator_validate/challenge.py:58-67`). The
  device entry sent to the page holds `device_class`, `device_uid` (the
  local DB key), `challenge` and `last_used`
  (`authentik/stages/authenticator_validate/stage.py:223-229`).
- The push happens inside validation of the POST that submits the Duo
  choice (`stage.py:104-108` → `challenge.py:258-314`). The response is used
  only for `result == "deny"` (`challenge.py:292`) and passed to the
  server-side `login_failed` signal (`challenge.py:294-305`). Deny and every
  `duo_client` error surface as the fixed string "Duo denied access"
  (`challenge.py:306, 314`); the error text goes to the admin event log
  (`challenge.py:309-313`). Success goes straight to the next stage
  (`stage.py:426-443`).
- The page component sends only `deviceUid` and renders the user info, a
  fixed "Sending Duo push notification..." while waiting, or the error
  strings (`web/src/flow/stages/authenticator_validate/AuthenticatorValidateStageDuo.ts:32-71`).
- Because `/auth` is synchronous, the page receives nothing until the user
  has already answered on the phone. A number in the response would arrive
  too late to be matched.

One channel does exist, at **enrollment** only: the setup stage passes the
server's `activation_barcode` (rendered as an `<img src>`) and
`activation_code` (rendered as a link) to the page
(`authentik/stages/authenticator_duo/stage.py:68-79`,
`web/src/flow/stages/authenticator_duo/AuthenticatorDuoStage.ts:78, 86`).
That is how the e2e test confirms enrollment reached the stub. It is not
on the login path.

Basis: source reading of the 2026.8.5 tag (Python files byte-identical to
the image). The e2e test shows the push POST blocking for the full delay
with no intermediate response, which is consistent with this but does not
prove the negative.

## Other observations

- The stub listens on 443 inside the compose network: `duo_client` always
  connects to port 443 on the configured hostname (`client.py:367-372`, no
  port option used by Authentik), so the API hostname cannot carry a port.
