# M0 findings

Feasibility spike results for PLAN.md §Milestones M0. Versions under test:
Authentik **2026.8.5** (`ghcr.io/goauthentik/server@sha256:602227a8…79a5`),
which bundles `duo_client` **5.6.1** and Python 3.14; Authentik LDAP outpost
**2026.8.5** (`ghcr.io/goauthentik/ldap@sha256:4c75bd27…ea87`); SSSD
**2.9.4-1.1ubuntu6.8** from Ubuntu 24.04 (`ubuntu@sha256:fe815609…f852`).

"Proven" means a test in this repo exercises it and was shown to fail when
the thing it checks is broken. "Inferred" means read from source, not
exercised.

| Item | Result | Basis |
|---|---|---|
| (a) sig v5 verification | **Pass** | Proven (unit + e2e) |
| (b) GTS chain passes `duo_client` pinning | Pending | Separate PR, real certificate |
| (c) blocking `/auth` survives ~60 s | **Pass** (60 s and 120 s) | Proven (e2e, measured) |
| (c′) upper limit on `/auth` blocking | ~215 s, then HTTP 408 | 240 s run measured; cause inferred from source |
| (d) push over an LDAP bind | **Pass** (plain password, no suffix) | Proven (e2e, measured) |
| (e) SSSD/PAM survives a 60 s approval | **Fail with defaults; pass with `ldap_opt_timeout = 90`** | Proven (e2e, measured) |
| (e′) SSSD with default timeouts sends a push every 8 s | **Yes**, until the backend is stopped | Proven (e2e, measured); cause from source |
| (e″) upper limit on an SSSD login | ~90 s (`client_idle_timeout`), then 120 s hard | 90 s and 120 s measured; 120 s cause inferred from source |
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
filters tests. The LDAP and SSSD tests need a delay above 10 s; CI runs the
whole suite at 60 s, so the 60 s measurement is also the CI run.

The LDAP outpost and the two SSSD containers (`sssd-default`,
`sssd-tuned`) are started by the test's `TestMain` once it has created the
LDAP provider, outpost and users, because the outpost needs its token. The
LDAP and PAM checks run inside the SSSD containers via
`docker compose exec` (`ldapsearch`, `pamtester`).

The SSSD logs are at debug level 6, which dumps the config, including the
run's throwaway service-account password; it dies with the stack.

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

## (d) push over an LDAP bind — Pass, proven

**Setup.** `TestMain` creates an LDAP provider (`base_dn dc=frict,dc=test`,
LDAPS with a test-CA certificate, `bind_mode`/`search_mode` direct,
`mfa_support: true`) whose bind flow is identification → password → Duo
validation (the stub's stage, `not_configured_action: skip`) → login, an
application and an LDAP outpost for it, and users whose Duo devices are
imported on the stub. The stub denies pushes for user ID `DUFRICTDENY`
(`-deny-user-ids`, after the same delay) and approves all others.

**What was checked.** `TestLDAPBindWaitsForPush` runs a simple bind plus a
base search (`ldapsearch -x -D cn=ldap-alice,… -w <password>`) over LDAPS
through the outpost. It requires success, an elapsed time of at least the
stub delay, and exactly one push for that user in the stub log.
`TestLDAPBindFailsWhenPushDenied` does the same for a denied user and requires
`invalidCredentials (49)`, at least the delay, and one push.

**Evidence.**

| Run | Approved bind | Denied bind | Log |
|---|---|---|---|
| stub delay 60 s | exit 0 after 1m3.052s, 1 push | exit 49 after 1m1.749s, 1 push | `ldap-e2e-60s/` |
| stub delay 30 s | exit 0 after 32.618s, 1 push | exit 49 after 31.755s, 1 push | `ldap-e2e-30s/` |
| final, 60 s | exit 0 after 1m2.553s, 1 push | exit 49 after 1m1.69s, 1 push | `ldap-final-e2e-60s/` |

The outpost logs the bind with its duration (`ldap.log`: `"Bind request"`,
`took-ms` 62607 for the approved bind in the 60 s run), and the stub logs one
`auth blocking` / `auth approved` (or `auth denied`) pair for the user's Duo
ID with `after=1m0.0…s`.

**How the bind password and the push interact.** The user types only their
password; the outpost sends the push. No TOTP suffix is needed.

- The outpost runs the provider's bind flow (`authorization_flow`,
  `authentik/providers/ldap/api.py:90`) through Authentik's flow executor for
  every direct-mode bind (`internal/outpost/ldap/bind/direct/bind.go:17-28`).
- `SetSecrets` (`internal/outpost/flow/solvers_mfa.go:11-37`): with
  `mfa_support` on, the bind password is split at its last `;` into password
  and code. With no `;` the whole string is the password and the code stays
  empty. With `mfa_support` off the whole string is also offered as the code.
- The validate-stage solver (`internal/outpost/flow/solvers.go:27-58`)
  selects the Duo device whenever the challenge offers one. It fills in a
  TOTP/static code only when the password carried one. Authentik's
  validate stage then calls Duo `/auth` synchronously
  (`authentik/stages/authenticator_validate/stage.py:104-108`), the same path
  as (c).
- Proven: a plain password with `mfa_support: true` triggers one push and
  binds once it is approved, and a denied push fails the bind with 49.
  Inferred, not tested: binds with `mfa_support: false`, or with a `;code`
  suffix, also push when the user has a Duo device. A password that contains
  `;` is cut at the last `;` when `mfa_support` is on, so that user can't bind.

**The push outlives the client.** The bind's context is a fresh Sentry span,
not tied to the LDAP connection (`internal/outpost/ldap/bind/request.go:27-49`),
and the flow executor's HTTP client has no timeout
(`internal/outpost/flow/executor.go:90-93`). When the client gives up, the
outpost keeps waiting and the login still completes in Authentik. Measured: in
`ldap-e2e-60s/ldap.log` every one of SSSD's abandoned binds for `ldap-bob`
(see (e)) finished with `took-ms` ≈ 62 300 and logged `User has access`, i.e. succeeded after SSSD
had dropped the connection at 8 s.

**Negative controls.**

- Deny switch removed (`-deny-user-ids=`) → `TestLDAPBindFailsWhenPushDenied`
  fails: exit 0 after 1m2.82s (`ldap-mut-deny-disabled/`).
- Pushes denied for the approving users too → `TestLDAPBindWaitsForPush`
  fails: exit 49 after 1m2.067s (`ldap-mut-approvers-denied/`).

**Service account.** SSSD searches with its own bind DN (`ldap-svc`, given
`search_full_directory` on the provider through a role). That bind goes
through the same flow. It has no Duo device, so the validate stage uses
`not_configured_action: skip`. That also lets *any* user without a Duo device
bind with a password alone. With PLAN's `frict-validate` (`configure`), the
service account's bind would fail: the outpost solves only identification,
password, validate and user-login challenges and errors on anything else
(`internal/outpost/flow/executor.go:213-215`; inferred, not tested). M5 has
to choose how the service account gets past the Duo stage.

## (e) SSSD/PAM vs a human approval — default fails, `ldap_opt_timeout = 90` passes

**Setup.** Two Ubuntu 24.04 containers with `sssd-ldap`, `libpam-sss`,
`libnss-sss` and `pamtester` (`e2e/sssd/Dockerfile`) talk LDAPS to the
outpost with the test CA. `sssd-default` runs `e2e/sssd/sssd-defaults.conf`
(every timeout at its default). `sssd-tuned` runs `e2e/sssd/sssd.conf`, which
is the same file plus one setting (`TestTunedSSSDIsDefaultsPlusPushTimeouts`
enforces this). Both use `cache_credentials = false`, so no cached offline
login can stand in for the server. The service account's password is written
into `conf.d` at container start and is not part of the committed files.
Every test runs `pamtester frict-test <user> authenticate` against
`auth required pam_sss.so`.

**Timeouts on the path (SSSD 2.9.4 source; the `ldap_*` defaults also appear
in the backend's option dump in each `sssd-*.log`).**

| Setting | Default | On the push path? |
|---|---|---|
| `ldap_opt_timeout` | 8 s | **Yes.** It is the timeout of the user's simple bind (`src/providers/ldap/ldap_auth.c:890-899` → `sdap_op_add`, `sdap_async.c:488-500`). |
| `ldap_network_timeout` | 6 s | Connect only (`sdap_async_connection.c:112`); the outpost accepts at once. |
| `ldap_search_timeout` | 6 s | The DN lookup before the bind; outpost searches return in well under 1 s. |
| `pam_id_timeout` | 5 s (`src/responder/pam/pamsrv.c:229`) | How long the PAM responder trusts cached identity data, not a wait on the auth. |
| `client_idle_timeout` | 60 s (`src/confdb/confdb.h:97`) | **Yes, above ~60 s.** The responder drops a client idle for more than this, checked every `client_idle_timeout/2` (`src/responder/common/responder_common.c:665-711`). Waiting on the backend counts as idle. |
| sbus call responder → backend | 120 s, fixed | **Yes, the hard ceiling.** `SBUS_MESSAGE_TIMEOUT 120000` (`src/sbus/sbus_message.h:33`, used at `src/sbus/request/sbus_request.c:660`); not configurable. |
| `pam_sss` client socket | 300 s, fixed | Above the sbus limit (`src/sss_client/sss_cli.h:436`). |
| `krb5_*`, domain `timeout` (watchdog) | — | Not relevant: `auth_provider = ldap`; the backend is event-driven, and the tuned 60 s pass shows the watchdog doesn't fire. |

**What happens with the defaults.** The bind times out after 8 s. SSSD
treats `ETIMEDOUT` as a network failure, reconnects and binds again, with no
retry limit (`src/providers/ldap/ldap_auth.c:925-933`). Each new bind is a new
flow execution in Authentik and so **a new push**. The outpost completes every
abandoned bind in Authentik (see (d)). `pamtester` gets
`Authentication service cannot retrieve authentication info` after 90 s,
when the PAM responder drops the idle client. The backend keeps binding after
that: in the first development run (`ldap-dev1/duo-stub.log`, 20 s delay)
two PAM attempts produced 58 pushes in five minutes, and the pushes stopped
only when the stack was torn down. The test therefore stops `sssd-default`
after its check.

**Evidence: default vs tuned at the same delay.**

| Run | `sssd-default` (defaults) | `sssd-tuned` (`ldap_opt_timeout = 90`) | `sssd-tuned`, denied push | Log |
|---|---|---|---|---|
| stub delay 60 s | **fail** after 1m30.188s, 12 pushes | **success** after 1m2.947s, 1 push | `Authentication failure` after 1m2.698s, 1 push | `ldap-e2e-60s/` |
| stub delay 30 s | **fail** after 1m30.255s, 11 pushes | **success** after 33.061s, 1 push | `Authentication failure` after 32.216s, 1 push | `ldap-e2e-30s/` |
| final, 60 s | **fail** after 1m30.212s, 11 pushes | **success** after 1m2.767s, 1 push | `Authentication failure` after 1m2.154s, 1 push | `ldap-final-e2e-60s/` |

In `sssd-tuned.log` (60 s run) the single bind for `ldap-carol` runs from
`simple_bind_send` at 18:04:45.339 to `Bind result: Success(0)` at
18:05:47.747, and the PAM responder returns `[0]: Success`. In `ldap-e2e-60s/`
the (c) test failed on an unrelated pre-existing bug (the device count; fixed
in this PR). Its LDAP and SSSD results stand, and the final run repeats them
all.

**Minimal tuned set: `ldap_opt_timeout = 90` alone.** It is the only setting
that differs between the two configs, and the default config fails at the same
delay, so no smaller set exists. Each other default on the table above was left
in place and the 60 s approval still passed. 90 s is chosen to sit just
under the client-idle cutoff (below) and above the push expiry. It also bounds
StartTLS and synchronous libldap calls, so a hung LDAP server now holds a
login for up to 90 s instead of 8.

**Upper limit (measured, partly inferred).**

- With `client_idle_timeout` at its default, `pamtester` is cut off at
  90 s in every default-config run (90.188, 90.255, 90.212 s, and 90.27 s with the defaults mounted in `sssd-tuned`). Experiment
  `ldap-exp-client-idle-300/` (defaults plus `[pam] client_idle_timeout =
  300`, 60 s delay): the same attempt ran to **2m0.633s** and failed with
  `System error`. The PAM responder logged `Returning [4]: System error`
  exactly 120 s after the request. So the 90 s cutoff is `client_idle_timeout`
  (proven: moving the setting moved the cutoff). The 120 s limit matches
  `SBUS_MESSAGE_TIMEOUT` (inferred from source).
- So with the reference config, an approval has to land in under ~88 s.
  Approvals up to just under 120 s would need `client_idle_timeout` raised as
  well, which was not measured with a successful approval. Nothing makes a
  ≥ 120 s approval work.

**Negative controls.** `ldap-mut-sssd-configs-swapped/` mounts each
container's config into the other: `TestSSSDTunedSurvivesPush` fails
(defaults in `sssd-tuned`: exit 1 after 1m30.17s, 12 pushes) and
`TestSSSDDefaultTimeoutsLosePush` fails (tuned config in `sssd-default`:
success after 1m3.227s, 1 push). `ldap-mut-deny-disabled/` makes
`TestSSSDTunedFailsWhenPushDenied` fail (success after 1m3.282s), and
`ldap-mut-approvers-denied/` makes `TestSSSDTunedSurvivesPush` fail (exit 1
after 1m2.249s). Editing `sssd-defaults.conf` without `sssd.conf` makes
`TestTunedSSSDIsDefaultsPlusPushTimeouts` fail
(`ldap-mut-unit-sssd-config-drift/`).

**Consequences for M1 and M5.**

- Frict's push expiry for LDAP logins must be **below `ldap_opt_timeout`**
  (90 s here) and below the ~88 s client-idle cutoff. Otherwise an unanswered
  push becomes a fresh push every `ldap_opt_timeout`, each one a real
  Authentik login if approved. 60 s fits.
- M5 must deploy the tuned `sssd.conf` *before* putting the Duo stage in the
  LDAP flow. With SSSD's defaults, every LDAP login floods the phone with
  pushes and still fails.
- Not tested: `cache_credentials = true` (offline logins), `su`/`sshd`/`gdm`
  PAM stacks (only `pam_sss` through `pamtester`), StartTLS (LDAPS only), and
  `bind_mode: cached` (it would cache a bind and skip the push on later binds;
  inferred from the mode's purpose, not read in source).

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
