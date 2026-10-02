#!/usr/bin/env bash
set -euo pipefail

: "${GITHUB_SHA:?The measured source commit is required}"

git fetch origin main
if [[ "$(git rev-parse origin/main)" != "$GITHUB_SHA" ]]; then
  echo "main has advanced; retain this run's metrics as artifacts and skip publication."
  exit 0
fi

git config user.name 'github-actions[bot]'
git config user.email '41898282+github-actions[bot]@users.noreply.github.com'
git add metrics/history.json metrics/code-size.svg metrics/coverage.svg metrics/dependency-inventory.md
if git diff --cached --quiet; then
  exit 0
fi
git commit -m 'chore: update project metrics'
if git push origin HEAD:main; then
  exit 0
fi

# A merge can land between the freshness check and the push. Never overwrite it
# or attach older measurements to that newer source commit.
git fetch origin main
if [[ "$(git rev-parse origin/main)" != "$GITHUB_SHA" ]]; then
  echo "main advanced during publication; retain this run's metrics as artifacts."
  exit 0
fi
echo 'Metrics publication failed while main was unchanged.' >&2
exit 1
