#!/bin/sh
# Rebuilds this checkout (app/build.sh) and checks every release recorded in
# app/builds.json whose source is identical to it: its hash must be this
# build's. That is how anyone confirms a deployed build is our published
# source. Run by CI; needs the full history (fetch-depth: 0).
set -eu
cd "$(dirname "$0")/.."
[ -f app/builds.json ] || { echo "no releases recorded"; exit 0; }
. app/source.sh
HASH=$(app/build.sh)
echo "this commit builds $HASH"
checked=0
for entry in $(node -e 'for (const b of JSON.parse(require("fs").readFileSync("app/builds.json"))) if (b.clean) console.log(`${b.commit}:${b.hash}`)'); do
  commit=${entry%%:*}; want=${entry#*:}
  git cat-file -e "$commit^{commit}" 2>/dev/null || { echo "release $want: commit $commit is not in this history" >&2; exit 1; }
  # Against the working tree, which is what app/build.sh just built.
  if git diff --quiet "$commit" -- $SOURCE; then
    [ "$want" = "$HASH" ] || { echo "release $want from $commit does not rebuild: got $HASH" >&2; exit 1; }
    echo "release $want from $commit rebuilds exactly"
    checked=$((checked + 1))
  fi
done
echo "$checked release(s) verified against this source"
