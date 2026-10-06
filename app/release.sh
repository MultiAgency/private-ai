#!/bin/sh
# Releases the hosted reviewer to OutLayer, in two passes, so that a build is
# published before it runs: the checker (core/receipt.mjs, through
# app/builds.json) trusts only recorded builds, and a review's receipt must
# check from the moment it is posted.
#
# 1. Builds (app/build.sh, reproducibly, from committed source) and, if this
#    build is not yet recorded, adds it to app/builds.json and stops: commit and
#    push that, then run this again.
# 2. Finds this build in the pushed app/builds.json (by its hash: the recorded
#    commit rebuilds to it, as CI checks) and releases it in the order that
#    keeps old builds harmless: upload, deploy without activating, move the
#    author secret's build lock to the new hash, activate, then remove every
#    other version (any published version stays callable by name until it is
#    removed).
#
# Usage: app/release.sh [--allow-dirty] [owner] [project]   (defaults: hack.near private-investigator)
# --allow-dirty records uncommitted source, as such (clean: false).
# Needs: Docker; an outlayer CLI with `secrets access --build` (out-layer/outlayer-cli
# main; the crates.io 0.1.2 lacks it), logged in as the owner.
set -eu
ALLOW_DIRTY=no
[ "${1:-}" = "--allow-dirty" ] && { ALLOW_DIRTY=yes; shift; }
OWNER=${1:-hack.near}
PROJECT=${2:-private-investigator}
PROFILE=private-investigator
cd "$(dirname "$0")/.."

. app/source.sh
DIRTY=$(git status --porcelain -- $SOURCE)
if [ -n "$DIRTY" ] && [ "$ALLOW_DIRTY" = no ]; then
  echo "uncommitted source; commit it first, or pass --allow-dirty:" >&2
  echo "$DIRTY" >&2
  exit 1
fi
HASH=$(app/build.sh)
WASM=target/repro/wasm32-wasip2/release/private-investigator.wasm
grep -q outlayer.manifest "$WASM" || { echo "the build has no outlayer.manifest section" >&2; exit 1; }
echo "build $HASH"

# Pass 1: record the build, unless the pushed record already holds it.
git fetch -q origin main
RECORDED=$(git show origin/main:app/builds.json 2>/dev/null | node -e '
const [hash, project] = process.argv.slice(1);
const b = JSON.parse(require("fs").readFileSync(0, "utf8")).find(b => b.hash === hash && b.project === project);
if (b) console.log(b.commit);' "$HASH" "$OWNER/$PROJECT" || true)
if [ -z "$RECORDED" ]; then
  COMMIT=$(git rev-parse HEAD)
  CLEAN=$([ -z "$DIRTY" ] && echo true || echo false)
  node -e '
const fs = require("fs"), [hash, commit, clean, project] = process.argv.slice(1);
const builds = fs.existsSync("app/builds.json") ? JSON.parse(fs.readFileSync("app/builds.json")) : [];
const known = builds.find(b => b.hash === hash && b.project === project);
if (known) console.log(`${hash} is already recorded here, built from ${known.commit}, but not on origin/main.`);
else {
  builds.push({ hash, commit, clean: clean === "true", project, recorded_at: new Date().toISOString() });
  fs.writeFileSync("app/builds.json", JSON.stringify(builds, null, 2) + "\n");
  console.log(`recorded ${hash}, built from ${commit}, in app/builds.json.`);
}' "$HASH" "$COMMIT" "$CLEAN" "$OWNER/$PROJECT"
  echo "Commit and push app/builds.json (the page then checks this build's receipts), then run app/release.sh again."
  exit 0
fi
echo "recorded on origin/main: built from $RECORDED"

# Upload in chunks (over 1 MB). An upload can report success yet never be
# served (a chunk lost on the way); if FastFS has not served the file within
# 3 minutes, upload once more, which has fixed it every time so far.
URL="https://main.fastfs.io/$OWNER/outlayer.near/$HASH.wasm"
served() {
  n=0
  until curl -sf -o /dev/null "$URL"; do   # FastFS answers GET only: a HEAD is always 404
    n=$((n + 1)); [ "$n" -lt 12 ] || return 1
    sleep 15
  done
}
for attempt in 1 2; do
  outlayer upload "$WASM" 2>&1 | tee /dev/stderr | grep -q "Upload complete" || { echo "upload failed" >&2; exit 1; }
  served && break
  [ "$attempt" = 2 ] && { echo "FastFS has not served $URL after two uploads" >&2; exit 1; }
  echo "not served after 3 minutes; uploading again" >&2
done

outlayer deploy "$PROJECT" "$URL" --hash "$HASH" --no-activate
outlayer secrets access --project "$OWNER/$PROJECT" --profile "$PROFILE" --build "$HASH"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
printf '[project]\nname = "%s"\nowner = "%s"\n' "$PROJECT" "$OWNER" > "$WORK/outlayer.toml"
(
  cd "$WORK"
  outlayer versions activate "$HASH"
  for old in $(outlayer versions | grep -oE '[0-9a-f]{64}' | grep -v "$HASH" | sort -u); do
    outlayer versions remove "$old"
  done
  outlayer versions
)
echo "released $HASH, built from $RECORDED (recorded in app/builds.json)"
