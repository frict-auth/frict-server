#!/bin/bash
# Sets the deployment server up, or upgrades it, from the files beside this
# script. deploy/install.sh carries them; docs/deploy.md runs it.
#
# Usage: setup.sh [PUBLIC_KEY]
# PUBLIC_KEY, one ssh-ed25519 line, becomes the deploy user's only key. Without
# it the installed key stays. frict.env and the Duo client secret are made only
# when missing.
set -euo pipefail
export LC_ALL=C PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
umask 022

src=$(dirname "$0")
user=frict-deploy
dir=/srv/frict
host=api.frict.app
key=${1-}

if (($# > 1)) || [[ -n $key && ! $key =~ ^ssh-ed25519\ [A-Za-z0-9+/]{68}(\ [[:print:]]*)?$ ]]; then
  echo "want at most one argument, one ssh-ed25519 public key line. Nothing changed." >&2
  exit 2
fi

visudo -cqf "$src/sudoers"
getent passwd "$user" >/dev/null || useradd --create-home --shell /bin/sh "$user"
home=$(getent passwd "$user" | cut -d: -f6)
install -d -o root -g root -m 0755 "$home/.ssh" "$dir"

exec 9>"$dir/.lock"
flock -n 9 || { echo "Waiting for the running deploy to finish."; flock 9; }

install -o root -g root -m 0755 "$src/frict-deploy" /usr/local/bin/frict-deploy
install -o root -g root -m 0440 "$src/sudoers" /etc/sudoers.d/frict-deploy
visudo -cq
install -o root -g root -m 0644 "$src/compose.yaml" "$dir/compose.yaml"
install -d -o 65532 -g 65532 -m 0700 "$dir/data" "$dir/secrets"

if [[ -n $key ]]; then
  printf 'restrict,command="/usr/bin/sudo -n /usr/local/bin/frict-deploy" %s\n' "$key" |
    install -o root -g root -m 0644 /dev/stdin "$home/.ssh/authorized_keys"
fi
secret=$dir/secrets/duo-client-secret
[[ -e $secret ]] || openssl rand -hex 20 | install -o 65532 -g 65532 -m 0400 /dev/stdin "$secret"
env=$dir/frict.env
[[ -e $env ]] || install -o root -g root -m 0600 /dev/stdin "$env" <<ENV
# frict-server's configuration. cmd/frict-server/main.go documents each variable.
# compose.yaml sets FRICT_LISTEN, FRICT_DB_PATH, FRICT_CLIENT_SECRET_FILE and FRICT_TRUSTED_PROXIES; its values win over this file.

# Needed now: the API hostname typed into Authentik's Duo stage.
FRICT_API_HOSTNAME=$host
# Needed now: the client ID typed into Authentik's Duo stage, with the secret in $secret.
FRICT_CLIENT_ID=DI$(openssl rand -hex 9 | tr a-f A-F)

# Only for push, later: the Firebase project to push through. Set both FCM lines or neither.
#FRICT_FCM_PROJECT_ID=
# Only for push, later: its FCM sender key, saved as $dir/secrets/fcm-sa.json.
#FRICT_FCM_CREDENTIALS_FILE=/secrets/fcm-sa.json

# Optional, default 60s: how long a push waits for the device's answer, 60s to 120s.
#FRICT_CHALLENGE_TTL=60s
# Optional, default 10: pushes since a user's last successful login before the cooldown applies.
#FRICT_PUSH_CAP=10
# Optional, default 15m: once over the cap, the least time between pushes.
#FRICT_PUSH_COOLDOWN=15m
# Optional, default 2: "I didn't start this" answers that pause the user's pushes ...
#FRICT_NOT_ME_COUNT=2
# Optional, default 60m: ... when given within this long.
#FRICT_NOT_ME_WINDOW=60m
# Optional, default 30m: how long the pause lasts.
#FRICT_PAUSE=30m
ENV

echo "Installed $user and $dir."
if [[ ! -s $home/.ssh/authorized_keys ]]; then
  echo "No deploy key: run this again with the public key line (docs/deploy.md)."
fi
cat <<MSG

On your workstation, save this server's host key for the deploy job:

printf '%s\n' '$host $(cut -d' ' -f1,2 /etc/ssh/ssh_host_ed25519_key.pub)' | gh secret set DEPLOY_KNOWN_HOSTS --repo frict-auth/frict-server --env production

Authentik's Duo stage: API hostname $(sed -n 's/^FRICT_API_HOSTNAME=//p' "$env"), client ID $(sed -n 's/^FRICT_CLIENT_ID=//p' "$env"),
client secret: sudo cat $secret
MSG
