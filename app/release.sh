#!/bin/sh
# Releases the hosted reviewer to OutLayer in the order that keeps old builds
# harmless: build, upload, deploy without activating, move the author secret's
# build lock to the new hash, activate, then remove every other version (any
# published version stays callable by name until it is removed).
#
# Usage: app/release.sh [--allow-dirty] [owner] [project]   (defaults: hack.near private-investigator)
# A release is built from committed source (app/build.sh, reproducibly) and
# recorded in app/builds.json, so its hash maps to a commit anyone can rebuild.
# --allow-dirty releases uncommitted source, recorded as such.
# Needs: an outlayer CLI with `secrets access --build` (out-layer/outlayer-cli
# main; the crates.io 0.1.2 lacks it), logged in as the owner.
set -eu
ALLOW_DIRTY=no
[ "${1:-}" = "--allow-dirty" ] && { ALLOW_DIRTY=yes; shift; }
OWNER=${1:-hack.near}
PROJECT=${2:-private-investigator}
PROFILE=private-investigator
cd "$(dirname "$0")/.."

SOURCE="app/src app/Cargo.toml app/manifest.json Cargo.toml Cargo.lock rust-toolchain.toml review/review.json"
DIRTY=$(git status --porcelain -- $SOURCE)
if [ -n "$DIRTY" ] && [ "$ALLOW_DIRTY" = no ]; then
  echo "uncommitted source; commit it first, or pass --allow-dirty:" >&2
  echo "$DIRTY" >&2
  exit 1
fi
HASH=$(app/build.sh)
WASM=target/wasm32-wasip2/release/private-investigator.wasm
grep -q outlayer.manifest "$WASM" || { echo "the build has no outlayer.manifest section" >&2; exit 1; }
echo "build $HASH"

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
# The release, for the record: which commit this hash is built from.
COMMIT=$(git rev-parse HEAD)
CLEAN=$([ -z "$DIRTY" ] && echo true || echo false)
node -e '
const fs = require("fs"), [hash, commit, clean, project] = process.argv.slice(1);
const builds = fs.existsSync("app/builds.json") ? JSON.parse(fs.readFileSync("app/builds.json")) : [];
builds.push({ hash, commit, clean: clean === "true", project, released_at: new Date().toISOString() });
fs.writeFileSync("app/builds.json", JSON.stringify(builds, null, 2) + "\n");' "$HASH" "$COMMIT" "$CLEAN" "$OWNER/$PROJECT"
if [ "$CLEAN" = true ]; then
  echo "released $HASH, built from $COMMIT (recorded in app/builds.json)"
else
  echo "released $HASH from uncommitted changes on $COMMIT (recorded as such in app/builds.json)" >&2
fi
