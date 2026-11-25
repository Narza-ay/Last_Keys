#!/usr/bin/env bash
# Verifies that the code affected by RUSTSEC-2026-0387 (crypto-bigint 0.5,
# pulled in transitively by opaque-ke 4 / elliptic-curve 0.13) is not linked
# into lk-auth. The advisory is ignored in deny.toml on that basis; if this
# check ever fails, the exception is no longer valid and must be revisited.
#
# Method: build the lk-auth test binaries with every crate unoptimized (no
# inlining can hide functions), then count symbols from the affected crate.
set -euo pipefail

target_dir="${CARGO_TARGET_DIR:-target}/advisory-check"
CARGO_TARGET_DIR="$target_dir" cargo test -p lk-auth --locked --no-run \
  --config 'profile.dev.package."*".opt-level=0' >/dev/null 2>&1

status=0
checked=0
for bin in "$target_dir"/debug/deps/opaque-*; do
  [[ -f "$bin" && -x "$bin" ]] || continue
  checked=$((checked + 1))
  affected=$(nm -C "$bin" | grep -c 'crypto_bigint' || true)
  reference=$(nm -C "$bin" | grep -c 'curve25519_dalek' || true)
  echo "$(basename "$bin"): crypto_bigint symbols=$affected (curve25519_dalek symbols=$reference)"
  if [[ "$reference" -eq 0 ]]; then
    echo "error: reference symbols missing; the check itself is broken" >&2
    status=1
  fi
  if [[ "$affected" -ne 0 ]]; then
    echo "error: crypto_bigint code is linked; RUSTSEC-2026-0387 exception is invalid" >&2
    status=1
  fi
done
if [[ "$checked" -eq 0 ]]; then
  echo "error: no lk-auth test binary found" >&2
  status=1
fi
exit "$status"
