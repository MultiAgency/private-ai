# The files a release is built from: a change to any of them can change the
# build. app/release.sh and app/verify-builds.sh both read this list, so
# "this hash is built from this commit" means the same thing to each.
SOURCE="app/build.sh app/src app/Cargo.toml app/manifest.json Cargo.toml Cargo.lock rust-toolchain.toml review/review.json"
