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
  followed by base32 (`A-Z`, `2-7`). One device per user, so outside
  enroll it names the key to verify with. The server rejects any other
  characters before it looks at the signature.
- `unix_seconds`: the signing time, decimal digits only.
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
`{"error": "<code>"}` with a matching HTTP status.

### `enroll` (signed with `device_key`)

The enrollment QR encodes `frict://enroll?host=<api host>&code=<activation code>`.

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
| `attestation` | Each key's Android Keystore attestation chain, leaf first, stored as sent. Each key is generated with the activation code as its attestation challenge, so M4 can check the chain is about this enrollment. Not verified until M4. |
| `fid` | Where to push. |

The user is the one `/auth/v2/enroll` issued this activation code for; the
server looks it up by the code and never takes it from the header. If the
header's `user_id` differs from that user, the request is rejected `401`.
Because `user_id` is also signed, a device holding its own valid code can't
enroll its keys under another user. The signature is checked against the
`device_key` in the body: proof that the device holds it. Answer: `200 {}`.
After this, Authentik's `enroll_status` for the user reports `success`.

### `challenge` (signed with `device_key`)

Request `{"challenge_id": "<22 chars>"}`. The ID is 16 random bytes,
base64url without padding. The FCM data message carries only this ID.

Response:

```json
{"challenge_id": "…", "username": "…", "ipaddr": "203.0.113.7",
 "pushinfo": "Domain=…&Application=…", "created": 1762345678, "expires": 1762345768}
```

`pushinfo` is passed through from Authentik's `/auth` call as sent.
`404` if the ID is unknown, belongs to another user, or is no longer
pending.

### `pending` (signed with `device_key`)

Request `{}`. Response `{"challenge_ids": ["…"], "poll_interval": 5}`: the
user's pending challenges, and how many seconds to wait before polling again
(server-set, as in CIBA).

### `answer` (signed with `approval_key`)

```json
{"challenge_id": "…", "decision": "deny", "reason": "not_me"}
```

| Field | Values |
|---|---|
| `decision` | `approve` or `deny` |
| `reason` | Required with `deny`, absent with `approve`: `not_me` ("I didn't start this": pauses pushes and alerts, see PLAN Safeguards) or `cancel`. |

`200 {}` on success; `409` if the challenge is no longer pending; `404` as for
`challenge`.

### `fid` (signed with `device_key`)

Request `{"fid": "…"}`. `200 {}`. A dead FID reported by FCM clears only the
stored FID, never the enrollment (PLAN Domain lessons).
