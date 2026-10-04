#!/usr/bin/env bash
set -euo pipefail

# Run on a Linux build host with the pinned musl target installed. This script
# only builds artifacts; it never boots a VM or performs guest mounts.
target="${TARGET_TRIPLE:-x86_64-unknown-linux-musl}"
target_dir="${CARGO_TARGET_DIR:-target}"
cargo build --locked --manifest-path guest-agent/Cargo.toml --target "$target" --release \
  --bin apollo-sandbox-guest \
  --bin apollo-sandbox-guest-bootstrap

agent="$target_dir/$target/release/apollo-sandbox-guest"
bootstrap="$target_dir/$target/release/apollo-sandbox-guest-bootstrap"
sha256sum "$agent" "$bootstrap"

# Set INITRAMFS_OUTPUT to produce the reviewed deterministic newc initramfs
# layout. /init is trusted PID1; the supervisor remains on the initramfs under
# /run/initramfs/staticagent and is opened by fd before the root switch.
if [[ -n "${INITRAMFS_OUTPUT:-}" ]]; then
  command -v cpio >/dev/null || { echo "cpio is required for INITRAMFS_OUTPUT" >&2; exit 1; }
  work="$(mktemp -d)"
  trap 'rm -rf "$work"' EXIT
  install -d -m 0755 \
    "$work/dev" "$work/proc" "$work/sys" "$work/mnt" "$work/run" \
    "$work/run/initramfs/staticagent" "$work/run/initramfs/statictool"
  install -m 0555 "$bootstrap" "$work/init"
  install -m 0555 "$agent" "$work/run/initramfs/staticagent/apollo-sandbox-guest"
  if [[ -n "${TRUSTED_NETWORK_TOOL:-}" ]]; then
    [[ -f "$TRUSTED_NETWORK_TOOL" && ! -L "$TRUSTED_NETWORK_TOOL" ]] || {
      echo "TRUSTED_NETWORK_TOOL must be a regular non-symlink file" >&2
      exit 1
    }
    install -m 0555 "$TRUSTED_NETWORK_TOOL" "$work/run/initramfs/statictool/network-tool"
  fi
  epoch="${SOURCE_DATE_EPOCH:-0}"
  touch -d "@$epoch" "$work/init" "$work/run/initramfs/staticagent/apollo-sandbox-guest"
  find "$work" -exec touch -h -d "@$epoch" {} +
  mkdir -p "$(dirname "$INITRAMFS_OUTPUT")"
  output_abs="$(cd "$(dirname "$INITRAMFS_OUTPUT")" && pwd)/$(basename "$INITRAMFS_OUTPUT")"
  (
    cd "$work"
    find . -print0 | LC_ALL=C sort -z | cpio --null --create --format=newc --owner=0:0 \
      > "$output_abs"
  )
  sha256sum "$output_abs"
fi
