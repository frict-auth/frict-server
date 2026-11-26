# Deploying frict-server

A merge to `main` that changes what the image is built from runs
`.github/workflows/deploy.yml`: it publishes the image, then the `deploy` job
waits for the approver. The build job's summary shows the digest and the
commits since the last successful deploy. To run it by hand: Actions → deploy →
Run workflow, on `main`.

Approving sends the digest over SSH to the deployment server's `frict-deploy`
user, whose key can only run `/usr/local/bin/frict-deploy` as root through
sudo. The user is not in the `docker` group and may run nothing else as root.
The script refuses anything that isn't a digest of this image and any build
older than the deployed one, backs up `data/`, starts the new version, and goes
back to the previous one if the new one isn't healthy. To go back on purpose,
revert on `main`.

## Setup

Run the `gh` blocks on your workstation, logged in as a repository admin, and
the rest where the step says. Blocks are in `( … )` so pasting one is safe.

### 1. `production` environment

Do this before the workflow first runs on `main`: GitHub creates a missing
environment without protection. Set `approver` to the GitHub login of the one
person who approves deploys.

```bash
(
set -e
approver=<login>
id=$(gh api "users/$approver" --jq .id)
repo=repos/frict-auth/frict-server/environments/production
gh api --method PUT "$repo" --input - <<JSON
{"prevent_self_review": false,
 "reviewers": [{"type": "User", "id": $id}],
 "deployment_branch_policy": {"protected_branches": false, "custom_branch_policies": true}}
JSON
gh api --method POST "$repo/deployment-branch-policies" -f name=main -f type=branch
)
```

Prevent-self-review is off because the approver is the only reviewer: with it
on they couldn't approve a run they started.

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

Expect `can_admins_bypass` false, one `required_reviewers` rule naming the
approver with `prevent_self_review` false, `custom_branch_policies` true, and
one policy: `main`, `branch`.

### 2. Deploy key

On your workstation, make the deploy key:

```bash
(
set -e
dir=$(mktemp -d)
trap 'rm -rf "${dir:?}"' EXIT
ssh-keygen -q -t ed25519 -N '' -C frict-deploy -f "$dir/key"
gh secret set DEPLOY_SSH_KEY --repo frict-auth/frict-server --env production < "$dir/key"
cat "$dir/key.pub"
)
```

The private key goes to the environment's secret and nowhere else; the block
prints the public key line for step 3. To change the key, repeat steps 2 and 3.

### 3. Deployment server

Needs Docker with Compose, `curl`, `openssl` and sudo. On the deployment
server, as a user with sudo, with `key` set to the line step 2 printed:

```bash
(
set -e
key='<public key line>'
dir=$(mktemp -d)
trap 'rm -rf "${dir:?}"' EXIT
cd "$dir"
curl -fsSLo install.sh -H 'Accept: application/vnd.github.raw+json' \
  https://api.github.com/repos/frict-auth/frict-server/git/blobs/76831c4c5c87a477b1e7304d34f28efd6213c7d7
echo '700cd036e15ffbe732180654a8fe8b8f4886731a275ec4abb721a67a9f65e98f  install.sh' | sha256sum --check --strict
sudo bash install.sh "$key"
)
```

The URL names `deploy/install.sh` by its git blob id, so it is the installer
this page describes, and `sha256sum` checks it before anything runs as root.
It carries `deploy/setup.sh` and the files that installs:

- user `frict-deploy`, without a password or the `docker` group, so the deploy
  key is its only way in;
- `/usr/local/bin/frict-deploy`, `/etc/sudoers.d/frict-deploy` and
  `/srv/frict/compose.yaml`, owned by root;
- the key as the only line of `~frict-deploy/.ssh/authorized_keys`, limited to
  `sudo -n /usr/local/bin/frict-deploy`;
- `/srv/frict/data` and `/srv/frict/secrets`;
- `/srv/frict/frict.env` and the Duo client secret, when missing.

It prints a `gh secret set DEPLOY_KNOWN_HOSTS` command, with this server's host
key: run it on your workstation. It also prints the API hostname, client ID and
where the client secret is, for Authentik's Duo stage.

Run the block again whenever `deploy/` changes; the workflow doesn't. With
`key` empty it keeps the installed key. It replaces the root-owned files and
keeps `frict.env`, the secrets and the data.

The sudoers rule lets `frict-deploy` run the script, without arguments, and
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

### What you have to fill in

Nothing, for the first deploy. The installer writes `/srv/frict/frict.env`
(`root:root`, mode 0600; edit it with `sudoedit`), which says what each
variable is for and its default. The client ID there and
`/srv/frict/secrets/duo-client-secret` are the pair you type into Authentik's
Duo stage; the installer generates both.

To enroll phones, uncomment and set:

| Variable | Value |
|---|---|
| `FRICT_APP_SIGNING_CERTS` | the release app's signing certificate SHA-256 digests, comma-separated |

In Play Console, for the release app (`app.frict.android`): Protected with
Play → Play Store distribution → Play app signing (older consoles: Test and
release → App integrity → App signing). Copy the **SHA-256 certificate
fingerprint** of the **App signing key certificate**, and of the **Upload key
certificate** only if phones run builds installed straight from the release
workflow rather than from Play. Paste them as shown (`AB:CD:…`, 32 pairs);
bare hex works too. SHA-1 fingerprints are refused. Restart to apply:
`sudo docker compose up --detach --force-recreate` in `/srv/frict`; the log
line `msg=attestation` counts the digests.

Until it is set, frict-server starts and serves logins, warns
`FRICT_APP_SIGNING_CERTS is empty`, and refuses every enrollment with an
`attestation_rejected` / `signing_cert` security line.
`compose.yaml` pins `FRICT_ATTESTATION` to `strict`; `frict.env` can't change
it.

To turn push on, uncomment and set both:

| Variable | Value |
|---|---|
| `FRICT_FCM_PROJECT_ID` | prod Firebase project |
| `FRICT_FCM_CREDENTIALS_FILE` | `/secrets/fcm-sa.json` |

and save the FCM sender key as that file, `65532:65532`, mode 0400:
`sudo install -o 65532 -g 65532 -m 0400 fcm-sa.json /srv/frict/secrets/`.

### 4. Package visibility

The deployment server pulls without credentials, which GHCR allows for public
packages only, and a package starts private. Until it is public the deploy job fails with
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

frict-server's own log is not in the job's log, which is public. On the
deployment server, `sudo docker compose logs frict-server` in `/srv/frict`
shows the live log; `/srv/frict/logs/` holds copies saved at deploy time.

A successful deploy keeps the backups in `/srv/frict/backups/` and the logs
in `/srv/frict/logs/` of the newest 5 deploys, its own always among them,
and deletes older ones; a failed deploy deletes nothing. A backup restores
the database as of its deploy, losing everything written since, so one more
than a few deploys old is not worth restoring. Files whose names don't start
with a deploy's stamp are left alone.

frict-server refuses a database newer than it knows. If the failed version
migrated it, going back can't work: the log says so, and the backup has to be
restored.

## Restore

`/srv/frict/.env` names the version that starts; it changes only when a
deploy succeeds. Restoring loses what was written after the backup. On the deployment server:

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
