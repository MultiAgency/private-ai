#!/bin/sh
# Builds the hosted reviewer reproducibly and prints its SHA-256: the pinned
# toolchain (rust-toolchain.toml), the locked dependencies, and no machine's
# paths in the binary (panic locations would otherwise name the builder's home
# and checkout). app/release.sh and CI build through this, so anyone can check
# that a deployed hash comes from a commit.
set -eu
cd "$(dirname "$0")/.."
CARGO_HOME=${CARGO_HOME:-$HOME/.cargo}
export RUSTFLAGS="--remap-path-prefix=$CARGO_HOME=/cargo --remap-path-prefix=$PWD=/private-ai ${RUSTFLAGS:-}"
cargo build --release --locked --target wasm32-wasip2 "$@" >&2
shasum -a 256 target/wasm32-wasip2/release/private-investigator.wasm | cut -d' ' -f1
