# Deploying frict-server

A merge to `main` that changes what the image is built from runs
`.github/workflows/deploy.yml`: it publishes the image, then the `deploy` job
waits for Geoffrey's approval. The build job's summary shows the digest and the
commits since the last successful deploy. To run it by hand: Actions → deploy →
Run workflow, on `main`.

Approving sends the digest over SSH to the box's `frict-deploy` user, whose key
can only run `/usr/local/bin/frict-deploy` as root through sudo. The user is not
in the `docker` group and may run nothing else as root. The script refuses
anything that isn't a digest of this image and any build older than the deployed
one, backs up `data/`, starts the new version, and goes back to the previous one
if the new one isn't healthy. To go back on
purpose, revert on `main`.

## Setup

Run the `gh` blocks on a machine logged in as `gfree76`, and the rest where the
step says. Blocks are in `( … )` so pasting one is safe.

### 1. `production` environment

Do this before the workflow first runs on `main`: GitHub creates a missing
environment without protection.

```bash
(
set -e
repo=repos/frict-auth/frict-server/environments/production
gh api --method PUT "$repo" --input - <<'JSON'
{"prevent_self_review": false,
 "reviewers": [{"type": "User", "id": 48987931}],
 "deployment_branch_policy": {"protected_branches": false, "custom_branch_policies": true}}
JSON
gh api --method POST "$repo/deployment-branch-policies" -f name=main -f type=branch
)
```

`48987931` is `gfree76`. Prevent-self-review is off because Geoffrey is the only
reviewer: with it on he couldn't approve a run he started.

Then, in the repo's Settings → Environments → production, clear **Allow
administrators to bypass configured protection rules** and save; the REST API
has no parameter for it. Check the result:

```bash
(
gh api repos/frict-auth/frict-server/environments/production \
  --jq '{can_admins_bypass, rules: [.protection_rules[] | {type, prevent_self_review, reviewers: [.reviewers[]?.reviewer.login]}], deployment_branch_policy}'
gh api repos/frict-auth/frict-server/environments/production/deployment-branch-policies --jq '.branch_policies[] | {name, type}'
)
```

Expect `can_admins_bypass` false, one `required_reviewers` rule with `gfree76`
and `prevent_self_review` false, `custom_branch_policies` true, and one policy:
`main`, `branch`.

### 2. Box

Needs Docker with Compose, `curl` and sudo. From a checkout of frict-server's
`main`, as a user with sudo:

```bash
(
set -e
getent passwd frict-deploy >/dev/null || sudo useradd --create-home --shell /bin/sh frict-deploy
sudo install -d -o root -g root -m 0755 /home/frict-deploy/.ssh
sudo install -o root -g root -m 0755 deploy/frict-deploy /usr/local/bin/frict-deploy
sudo visudo -cqf deploy/sudoers
sudo install -o root -g root -m 0440 deploy/sudoers /etc/sudoers.d/frict-deploy
sudo visudo -cq
sudo install -d -o root -g root -m 0755 /srv/frict
sudo install -o root -g root -m 0644 deploy/compose.yaml /srv/frict/compose.yaml
sudo install -d -o 65532 -g 65532 -m 0700 /srv/frict/data /srv/frict/secrets
)
```

Repeat it when `deploy/` changes; the workflow doesn't. `frict-deploy` gets no
password, so it can't log in other than with the deploy key.

`deploy/sudoers` lets `frict-deploy` run the script, without arguments, and
passes it `SSH_ORIGINAL_COMMAND` and no other variable from the SSH session.

Check the user's groups and sudo rights:

```bash
(
id -nG frict-deploy
sudo -l -U frict-deploy | sed '1,/may run the following commands/d'
)
```

Expect `frict-deploy` alone, then `(root) NOPASSWD: /usr/local/bin/frict-deploy ""`.
`docker` among the groups means the user can become root without the script.

**Configuration**: `/srv/frict/frict.env`, `root:root`, mode 0600.
`cmd/frict-server/main.go` documents each variable.

| Variable | Value | Set in |
|---|---|---|
| `FRICT_API_HOSTNAME` | `api.frict.app` | `frict.env`, required |
| `FRICT_CLIENT_ID` | Duo stage client ID | `frict.env`, required |
| `FRICT_TRUSTED_PROXIES` | gateway of the `frict_default` network (`docker network inspect frict_default`) | `frict.env` |
| `FRICT_FCM_PROJECT_ID` | prod Firebase project | `frict.env`, both or neither |
| `FRICT_FCM_CREDENTIALS_FILE` | `/secrets/fcm-sa.json` | `frict.env`, both or neither |
| `FRICT_CHALLENGE_TTL`, `FRICT_PUSH_CAP`, `FRICT_PUSH_COOLDOWN`, `FRICT_NOT_ME_COUNT`, `FRICT_NOT_ME_WINDOW`, `FRICT_PAUSE` | default if unset | `frict.env`, optional |
| `FRICT_LISTEN`, `FRICT_DB_PATH`, `FRICT_CLIENT_SECRET_FILE` | fixed | `compose.yaml` |

No variable is itself secret. The secrets are two files in
`/srv/frict/secrets/`, `65532:65532`, mode 0400: `duo-client-secret`
(the Duo stage's client secret) and, for push, `fcm-sa.json` (the FCM sender
key). Generate the first on the box:

```bash
(
set -e
f=/srv/frict/secrets/duo-client-secret
sudo test -e "$f" || openssl rand -hex 20 | sudo install -o 65532 -g 65532 -m 0400 /dev/stdin "$f"
)
```

### 3. Deploy key

On the desktop:

```bash
(
set -e
umask 077
mkdir -p ~/keystores
test -e ~/keystores/frict-deploy || ssh-keygen -q -t ed25519 -N '' -C frict-deploy -f ~/keystores/frict-deploy
printf 'restrict,command="/usr/bin/sudo -n /usr/local/bin/frict-deploy" %s\n' "$(cat ~/keystores/frict-deploy.pub)"
)
```

On the box, make the line it prints the only line of
`/home/frict-deploy/.ssh/authorized_keys` (`sudo nano /home/frict-deploy/.ssh/authorized_keys`).

### 4. Host key and secrets

On the box, print its host key as a known_hosts line:

```bash
printf 'api.frict.app %s\n' "$(cut -d' ' -f1,2 /etc/ssh/ssh_host_ed25519_key.pub)"
```

On the desktop, save that line as `~/keystores/frict-known-hosts`, then:

```bash
(
set -e
gh secret set DEPLOY_SSH_KEY --repo frict-auth/frict-server --env production < ~/keystores/frict-deploy
gh secret set DEPLOY_KNOWN_HOSTS --repo frict-auth/frict-server --env production < ~/keystores/frict-known-hosts
)
```

Check the key from the desktop. `REFUSED` and nothing else means it works:

```bash
ssh -i ~/keystores/frict-deploy -o IdentitiesOnly=yes -o UserKnownHostsFile=~/keystores/frict-known-hosts frict-deploy@api.frict.app nothing
```

### 5. Package visibility

The box pulls without credentials, which GHCR allows for public packages only,
and a package starts private. Until it is public the deploy job fails with
`REFUSED: cannot pull`, changing nothing. After the first build job:

1. Organization settings → Packages → Package creation: allow **Public**.
2. [frict-server package](https://github.com/orgs/frict-auth/packages/container/package/frict-server)
   → Package settings → Danger Zone → Change visibility → **Public**. This can't
   be undone.

Then approve the deploy, or re-run the failed job.

## When a deploy fails

The job's log ends with one of these:

| Message | State |
|---|---|
| `REFUSED` | Nothing changed. |
| `WENT BACK` | The previous version is running. |
| `SERVER IS DOWN` | Nothing is serving. |

frict-server's own log is on the box in `/srv/frict/logs/` (readable with sudo),
not in the job's log, which is public.

frict-server refuses a database newer than it knows. If the failed version
migrated it, going back can't work: the log says so, and the backup has to be
restored.

## Restore

`/srv/frict/.env` names the version that starts; it changes only when a
deploy succeeds. Restoring loses what was written after the backup. On the box:

```bash
(
set -e
cd /srv/frict
sudo test -e backups/<backup>.tar
sudo docker compose stop
sudo rm -f data/frict.db data/frict.db-wal data/frict.db-shm
sudo tar --numeric-owner -xf backups/<backup>.tar
sudo docker compose up --detach --force-recreate
)
```

To restore a backup older than the last deploy, first set `FRICT_DIGEST` in
`.env` to the version that wrote it: the one deployed before the backup's own
deploy.
