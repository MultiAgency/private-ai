#!/bin/sh
# Builds the hosted reviewer reproducibly and prints its SHA-256. The build runs
# in a pinned Linux x86-64 container with the pinned toolchain
# (rust-toolchain.toml) and the locked dependencies, at fixed paths, because
# the same source builds different bytes on different hosts (a Mac, Linux on
# ARM and Linux on x86 each gave their own hash). app/release.sh and CI build
# through this, so anyone with Docker can check that a deployed hash comes from
# a commit.
set -eu
cd "$(dirname "$0")/.."
IMAGE=rust:1.97.0@sha256:b92b8c8574f8f3b207fcb0912fb3e2de4041580b5934d90312d53938c9a038a9
OUT=target/repro/wasm32-wasip2/release/private-investigator.wasm
docker run --rm --platform linux/amd64 \
  -v "$PWD":/private-ai -w /private-ai \
  -v private-ai-cargo-registry:/cargo/registry \
  -e CARGO_HOME=/cargo -e CARGO_TARGET_DIR=/private-ai/target/repro \
  "$IMAGE" cargo build --release --locked --target wasm32-wasip2 "$@" >&2
shasum -a 256 "$OUT" | cut -d' ' -f1
