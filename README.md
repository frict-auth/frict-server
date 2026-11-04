This is where we'll put docs about frict-server

## cross-review status poster

`cmd/cross-review-status` posts the `cross-review` commit status that the
ruleset requires, as the `frict-cross-review` GitHub App (App ID 5557312,
permission Commit statuses: write). It signs an App JWT, asks for an
installation token limited to `statuses:write` on the one repo, and posts the
status on a full 40-hex SHA.

```bash
go build -o cross-review-status ./cmd/cross-review-status
./cross-review-status --repo frict-auth/frict-server --sha <40-hex sha> \
  --state success --description "reviewed by <vendor>" --target-url <review link>
```

`--state` is `pending`, `success`, `failure` or `error`. The key defaults to
`~/.config/frict/cross-review.pem` (`--key-file`) and must be mode 600 or
stricter; the tool refuses keys readable by group or other.

The gate is a process guard, not a security boundary. It stops a stray token
from marking a PR reviewed. Any process that can read the key can post any
state on any commit in repos where the App is installed.
