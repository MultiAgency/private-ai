#!/bin/sh
# Releases the hosted reviewer to OutLayer, in one go, from what is on GitHub:
#
# 1. Builds this checkout, which must be origin/main (app/build.sh, reproducibly).
# 2. Records the build in app/builds.json, then commits and pushes that record
#    (as you: your signing prompt appears), unless it is recorded already. The
#    checker (core/receipt.mjs) trusts only recorded builds, so a review's
#    receipt checks from the moment it is posted.
# 3. Waits until the page has published the record.
# 4. Releases the build in the order that keeps old builds harmless: upload,
#    deploy without activating, move the author secret's build lock to the new
#    hash, activate, then remove every other version (any published version
#    stays callable by name until it is removed).
#
# Run it again after a failure: a recorded build is not recorded twice.
# Usage: app/release.sh [--allow-dirty] [owner] [project]   (defaults: hack.near private-investigator)
# --allow-dirty releases uncommitted source, recorded as such (clean: false).
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
git fetch -q origin main
if [ "$ALLOW_DIRTY" = no ] && [ "$(git rev-parse HEAD)" != "$(git rev-parse origin/main)" ]; then
  echo "this checkout is not origin/main: push your changes (or pull), then release" >&2
  exit 1
fi
HASH=$(app/build.sh)
WASM=target/repro/wasm32-wasip2/release/private-investigator.wasm
grep -q outlayer.manifest "$WASM" || { echo "the build has no outlayer.manifest section" >&2; exit 1; }
echo "build $HASH"

# The record, on origin/main: which commit this hash is built from.
RECORDED=$(git show origin/main:app/builds.json 2>/dev/null | node -e '
const [hash, project] = process.argv.slice(1);
const b = JSON.parse(require("fs").readFileSync(0, "utf8")).find(b => b.hash === hash && b.project === project);
if (b) console.log(b.commit);' "$HASH" "$OWNER/$PROJECT" || true)
if [ -z "$RECORDED" ]; then
  if [ -n "$(git status --porcelain -- app/builds.json)" ]; then
    echo "app/builds.json has changes of its own; commit or drop them, then release" >&2
    exit 1
  fi
  RECORDED=$(git rev-parse HEAD)
  CLEAN=$([ -z "$DIRTY" ] && echo true || echo false)
  node -e '
const fs = require("fs"), [hash, commit, clean, project] = process.argv.slice(1);
const builds = fs.existsSync("app/builds.json") ? JSON.parse(fs.readFileSync("app/builds.json")) : [];
builds.push({ hash, commit, clean: clean === "true", project, recorded_at: new Date().toISOString() });
fs.writeFileSync("app/builds.json", JSON.stringify(builds, null, 2) + "\n");' "$HASH" "$RECORDED" "$CLEAN" "$OWNER/$PROJECT"
  # A commit that doesn't happen (a cancelled signing prompt, say) leaves no
  # stray record behind, so running this again starts clean.
  if ! git commit -q -m "Record build $(echo "$HASH" | cut -c1-8)" -- app/builds.json; then
    git checkout -q -- app/builds.json
    echo "the record wasn't committed, so nothing was released; run this again" >&2
    exit 1
  fi
  git push -q origin HEAD:main
  echo "recorded $HASH, built from $RECORDED, and pushed the record"
else
  echo "recorded on origin/main: built from $RECORDED"
fi

# The page publishes the record on each push to main (the pages workflow); the
# first review from this build must find it there.
PAGE=${PAGE:-https://multiagency.github.io/private-ai/app.js}
n=0
until curl -sf "$PAGE" | grep -q "$HASH"; do
  n=$((n + 1)); [ "$n" -lt 40 ] || { echo "the page has not published the record after 10 minutes; check the pages workflow, then run this again" >&2; exit 1; }
  sleep 15
done
echo "the page checks receipts from this build"

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
