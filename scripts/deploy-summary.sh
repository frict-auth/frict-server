#!/usr/bin/env bash
# Prints what approving a deploy of DIGEST would change, as Markdown: the
# digest, the commit, and the commits on main since the last successful deploy.
#   deploy-summary.sh DIGEST
# Needs a full clone of main, gh, and Actions' GITHUB_* variables.
set -euo pipefail
digest="$1"
repo="$GITHUB_SERVER_URL/$GITHUB_REPOSITORY"

# A successful run of deploy.yml on main has deployed. Runs of commits that
# aren't in HEAD's history don't count, whatever branch or tag they name.
shas="$(gh api "repos/$GITHUB_REPOSITORY/actions/workflows/deploy.yml/runs?branch=main&status=success&per_page=100" \
  --jq '.workflow_runs | sort_by(-.run_number) | .[].head_sha')"
last=
for sha in $shas; do
  if git merge-base --is-ancestor "$sha" HEAD; then
    last="$sha"
    break
  fi
done

echo "## Deploying this run's image"
echo
echo "- Image: \`ghcr.io/frict-auth/frict-server@$digest\`"
echo "- Commit: [\`$GITHUB_SHA\`]($repo/commit/$GITHUB_SHA) ([checks]($repo/commit/$GITHUB_SHA/checks))"
if [ -z "$last" ]; then
  echo "- Last successful deploy: none found; the list is all of main"
  range=HEAD
else
  echo "- Last successful deploy: [\`$last\`]($repo/commit/$last), [compare]($repo/compare/$last...$GITHUB_SHA)"
  range="$last..HEAD"
fi
echo
echo '````'
git log --format='%h %s' "$range"
echo '````'
