# Device protocol

The API between the Frict app and `frict-server`, as M1 needs it. Authentik
never sees it; it speaks Duo's Auth API on `/auth/v2/*`.

## Choice: a small custom signature, not RFC 9421 or WebAuthn

Only our app talks to this API, so a standard buys no interoperability here.
What it would cost:

- **RFC 9421 HTTP Message Signatures** (`ecdsa-p256-sha256`) needs a
  Structured Fields (RFC 8941) parser and serializer for `Signature-Input`,
  plus `Content-Digest` (RFC 9530) for the body. Neither the Go standard
  library nor Android ships one, so both sides would hand-write them: more
  custom code than the scheme below. It also wants the signature as raw
  `r||s`, while Android's `SHA256withECDSA` and Go's `ecdsa.VerifyASN1` both
  use ASN.1 DER, so both sides would convert.
- **WebAuthn-style** signing (`authenticatorData || sha256(clientDataJSON)`)
  carries fields (RP ID hash, flags, sign counter, origin) that mean nothing
  outside a browser authenticator.

So the device signs one fixed byte string, the same shape as Duo's sig v5
that `internal/duosig` already verifies, with ECDSA P-256 / SHA-256 and DER
signatures: the formats both platforms produce and consume natively.

## Keys

Each device holds two non-exportable P-256 keys in StrongBox/TEE:

| Key | User auth | Signs |
|---|---|---|
| `device_key` | none | enroll, challenge fetch, poll, FID update |
| `approval_key` | biometric on every use | answers only |

Two keys because PLAN requires a biometric on every use of the approval
key, and FID updates and polls run in the background with no user present.
Fetching a challenge's details also must not cost a fingerprint before the
user has seen what they are approving. Only an answer needs the user.

Public keys travel as X.509 SubjectPublicKeyInfo DER (`PublicKey.getEncoded()`
on Android, `x509.ParsePKIXPublicKey` in Go), base64url without padding.

## Request signing

Every device request is `POST` with a JSON body (possibly `{}`) and no query
string. It carries:

```
Authorization: Frict-P256 <user_id>:<unix_seconds>:<signature>
```

- `user_id`: the Duo user ID Frict issued at `/auth/v2/enroll`: `DU`
  followed by exactly 26 base32 characters (`A-Z`, `2-7`). One device per
  user, so outside enroll it names the key to verify with. The server
  rejects anything else before it looks at the signature.
- `unix_seconds`: the signing time, 1 to 12 decimal digits.
- `signature`: base64url (no padding) ASN.1 DER ECDSA-SHA256 over the
  signed bytes below.

Signed bytes, UTF-8, joined by `\n`:

```
frict-device-v1
<user_id>
<unix_seconds>
<path>
<body>
```

The layout can't be read two ways: the tag, `user_id` (base32), `unix_seconds`
(digits) and `path` (one of the fixed routes below) can't contain `\n`, so
the first four `\n` end the first four fields, and the body is everything
after the fourth, newlines included.

| Field | Why |
|---|---|
| `frict-device-v1` | A signature made for this API can't be valid anywhere else, including a later version of it. |
| `user_id` | Binds the request to one user. At enroll the key to verify with comes from the body, so without this a valid signature says nothing about which user it is for. |
| `unix_seconds` | Bounds replay: see Verification. |
| `path` | Binds the signature to one endpoint, so an answer can't be replayed as an FID update. |
| `body` | Binds the parameters. Last, so no separator inside it is ambiguous. |

Left out, and why that is safe:

| Omitted | Why |
|---|---|
| Method | The server routes only `POST` on these paths; any other method is rejected before verification. |
| Host | Outside enroll, the server verifies against a key it stored at that user's enrollment, which no other server holds. An enroll request carries an activation code that only the issuing server knows and that is single use. |
| Nonce | Replay is bounded by the time window and single-use state; see Replay. |

### Verification

The server, in this order:

1. Parses the header. `user_id` and `unix_seconds` must match the formats
   above.
2. Checks freshness on the header's `unix_seconds`: more than 5 minutes from
   the server's clock, either way, is rejected. There is no other time
   field.
3. Rebuilds the signed bytes from the tag, the header's `user_id`, the
   header's `unix_seconds`, the request path and the raw body as received.
4. Verifies the signature with the key the path calls for. At enroll that is
   the body's `device_key`, and the user is fixed by the activation code
   (see `enroll`).

Outside enroll, the key is the header user's stored `approval_key` for
`/device/v1/answer` and `device_key` otherwise. Any failure is answered `401`,
without saying which part failed.

### Replay

TLS already stops an on-path replay. The signature scheme limits what a
captured request (a proxy log, a debug dump) is worth:

- **Answers** name their `challenge_id`, and a challenge leaves `pending` once,
  atomically. A replayed answer finds it answered or expired and gets `409`.
  Single use is what stops this, not the time window, which outlasts the
  challenge's 60–120 s expiry.
- **Enroll** carries a single-use activation code.
- **Fetch and poll** are reads; a replay within 5 minutes returns what the
  original did.
- **FID update** replayed within 5 minutes can set an FID the device has since
  replaced. The device fixes it on its next update; the worst case is missed
  pushes, which polling covers.

A server-issued nonce would close the last two, at the cost of a round trip
and server state on every request. Not worth it for a read and an FID.

## Endpoints

All under `https://<api host>/device/v1/`. Responses are JSON. Errors are
`{"error": "<code>"}` with a matching HTTP status:

| Status | `error` | When |
|---|---|---|
| 400 | `bad_request` | The body doesn't parse, has unknown or missing fields, or a value outside those listed below. |
| 401 | `unauthorized` | Any verification failure, including a user with no enrolled device. |
| 404 | `not_found` | See each endpoint. |
| 409 | `not_pending` | `answer` only. |

The signature is checked before the body is parsed, so an unsigned or
badly signed request gets `401` whatever its body.

### Activation (Duo side)

Authentik's Duo setup stage calls `/auth/v2/enroll` with only `username`
(`duo_client/auth.py:43-67`, called from
`authentik/stages/authenticator_duo/stage.py:57`). Frict answers:

| Field | Value |
|---|---|
| `user_id` | A new `DU` + 26 base32 user ID. Every call creates a new user. |
| `activation_code` | The app link `frict://enroll?code=<code>&host=<api host>&user_id=<user_id>`. Authentik renders it as a link (`web/src/flow/stages/authenticator_duo/AuthenticatorDuoStage.ts`). |
| `activation_barcode` | The same link. Authentik renders it as an image source; Frict does not render a QR image yet (see PLAN Open). |
| `username` | As sent. |
| `valid_secs` | `900`. Authentik sends no `valid_secs`. |

`<code>` is 128 random bits as 26 base32 characters. The server keeps only
its SHA-256. It enrolls one device, within `valid_secs`.

`/auth/v2/enroll_status` gets `user_id` and that link back
(`stage.py:85-87`, and every 3 s from the setup page through
`api.py:95-106`) and answers `waiting` while the code is unclaimed and
unexpired, `success` once a device has enrolled with it (also after
expiry), and `invalid` otherwise. The page submits on `success`.

### `enroll` (signed with `device_key`)

The app reads `host`, `user_id` and `code` from the activation link, sends
`user_id` in the `Authorization` header and `code` as `activation_code`.

```json
{
  "activation_code": "…",
  "device_key": "<SPKI, base64url>",
  "approval_key": "<SPKI, base64url>",
  "attestation": {
    "device_key": ["<cert DER, base64url>", "…"],
    "approval_key": ["…"]
  },
  "fid": "…"
}
```

| Field | Why |
|---|---|
| `activation_code` | Proves the device scanned this user's QR. Single use; it expires with Duo's `valid_secs`. |
| `device_key`, `approval_key` | See Keys. |
| `attestation` | Each key's Android Keystore attestation chain, leaf first, stored as sent. Each key is generated with the activation code as its attestation challenge, so M4 can check the chain is about this enrollment. Each chain must be a non-empty list of base64url strings; the certificates are not verified until M4. |
| `fid` | Where to push. |

The user is the one `/auth/v2/enroll` issued this activation code for; the
server looks it up by the code and never takes it from the header. If the
header's `user_id` differs from that user, the request is rejected `401`.
Because `user_id` is also signed, a device holding its own valid code can't
enroll its keys under another user. The signature is checked against the
`device_key` in the body: proof that the device holds it. Answer: `200 {}`.
After this, Authentik's `enroll_status` for the user reports `success`.

Every failure is `401 {"error": "unauthorized"}`: a bad header, timestamp or
signature, a body with unknown or missing fields or a key that is not
P-256, and an activation code that is unknown, expired, already used or
issued for another user.

### Login (Duo side)

Authentik's Duo validation stage calls `/auth/v2/auth` synchronously with
`factor=auto`, `async=0`, `user_id`, `ipaddr`, `type`, `display_username`,
`device=auto` and `pushinfo`
(`authentik/stages/authenticator_validate/challenge.py:276-290`). Frict
answers `400` (`stat: FAIL`) for `async=1`, a factor other than `auto` or
`push`, or a `user_id` with no enrolled device; Authentik records that as a
configuration error (`challenge.py:307-314`).

Otherwise Frict creates a challenge and holds the call open until the
device answers, the challenge expires (`FRICT_CHALLENGE_TTL`, 60–120 s,
default 60 s), or Authentik's request ends. A challenge leaves `pending`
when it is answered, or becomes `expired` when it times out or the call
ends, so the device never sees a challenge nobody is waiting on.

The response is `stat: OK` with Duo's `result`, `status` and `status_msg`.
Authentik reads only `result` (`challenge.py:292`) but records the whole
response in its `login_failed` event on a deny (`challenge.py:294-305`,
under `auth_method_args.duo_response`), so the `status` values are Duo's
own (duo.com/docs/authapi, `/auth` status values):

| Outcome | `result` | `status` | `status_msg` |
|---|---|---|---|
| approve | `allow` | `allow` | `Success. Logging you in...` |
| deny, `cancel` | `deny` | `deny` | `Login request denied.` |
| deny, `not_me` | `deny` | `fraud` | `Login request reported as fraudulent.` |
| expired | `deny` | `timeout` | `Login timed out.` |

### `challenge` (signed with `device_key`)

Request `{"challenge_id": "<22 chars>"}`. The ID is 16 random bytes,
base64url without padding. The FCM data message carries only this ID.

Response:

```json
{"challenge_id": "…", "username": "…", "ipaddr": "203.0.113.7",
 "pushinfo": "Domain=…&Application=…", "type": "authentik Login request",
 "created": 1762345678, "expires": 1762345768}
```

`username` (Authentik's `display_username`), `ipaddr`, `pushinfo` and
`type` are passed through from Authentik's `/auth` call as sent; any of
them may be empty. `created` and `expires` are unix seconds.
`404` if the ID is unknown, belongs to another user, or is no longer
pending.

### `pending` (signed with `device_key`)

Request `{}`: an object with no fields. Response
`{"challenge_ids": ["…"], "poll_interval": 5}`: the user's pending,
unexpired challenges, oldest first (an empty list when there are none), and
how many seconds to wait before polling again (server-set, as in CIBA).

### `answer` (signed with `approval_key`)

```json
{"challenge_id": "…", "decision": "deny", "reason": "not_me"}
```

| Field | Values |
|---|---|
| `decision` | `approve` or `deny` |
| `reason` | Required with `deny`, absent with `approve`: `not_me` ("I didn't start this": pauses pushes and alerts, see PLAN Safeguards) or `cancel`. |

Any other combination, including `deny` with no `reason`, is `400`.
`200 {}` on success; `409` if the challenge was already answered or has
expired, however recently; `404` if the ID is unknown or belongs to another
user. Only the first answer counts.

### `fid` (signed with `device_key`)

Request `{"fid": "…"}`. `200 {}`. A dead FID reported by FCM clears only the
stored FID, never the enrollment (PLAN Domain lessons).
