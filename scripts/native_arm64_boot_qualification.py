#!/usr/bin/env python3
"""Run the isolated host-native AArch64 Firecracker boot contract."""
import base64
import json
import subprocess
import tempfile
from pathlib import Path

from revision import ROOT

STATE = "/var/lib/apollo-sandboxd/native-arm64"
BASE = "/opt/apollo-sandboxd/reference-images/aarch64/02f9edde67cd3f4db7c1e1a8ebdc65557cfdf450dcd4841f47a9570d8635126e/rootfs.ext4"
BASE_DIGEST = "02f9edde67cd3f4db7c1e1a8ebdc65557cfdf450dcd4841f47a9570d8635126e"
FORMATTER = "/opt/apollo-sandboxd/storage-tools/84419f91298e173cf1569b3a9c957c9f3e26a28852a6025800ed9e0cd9227ea2/mke2fs"
FORMATTER_DIGEST = "84419f91298e173cf1569b3a9c957c9f3e26a28852a6025800ed9e0cd9227ea2"


def main() -> int:
    config = (ROOT / "qualification/native-arm64/sandboxd.toml").read_bytes()
    config_b64 = base64.b64encode(config).decode()
    commands = [
        ["sudo", "-n", "install", "-d", "-m", "700", STATE, f"{STATE}/state", f"{STATE}/drives", "/a64", "/a64/firecracker", "/run/apollo-sandboxd-native-arm64"],
        ["sudo", "-n", "bash", "-lc", "set -euo pipefail; if ! mountpoint -q /a64/firecracker; then mount --bind /a64/firecracker /a64/firecracker; fi; mount --make-private /a64/firecracker"],
        ["sudo", "-n", "chmod", "0555", "/opt/apollo-sandboxd/runtime-catalog/aarch64/v1.17.0/firecracker", "/opt/apollo-sandboxd/runtime-catalog/aarch64/v1.17.0/jailer", FORMATTER],
        ["sudo", "-n", "find", STATE, "-maxdepth", "1", "-type", "f", "-name", "strace.*", "-delete"],
        ["sudo", "-n", "python3", "-c", f"import base64,os; p='{STATE}/sandboxd.toml'; open(p,'wb').write(base64.b64decode('{config_b64}')); os.chmod(p,0o600)"],
        ["cargo", "test", "--locked", "--test", "native_boot_contract", "native_firecracker_boot_exec_process_limit_file_and_pty", "--no-run"],
        ["bash", "-lc", f"set -euo pipefail; test_bin=$(find target/debug/deps -maxdepth 1 -type f -name 'native_boot_contract-*' -perm /111 -print -quit); test -n \"$test_bin\"; sudo -n strace -ff -tt -s 512 -e trace=process,execve,connect,bind,listen,openat,write -o {STATE}/strace env HOME=/home/apollo-admin RUSTUP_HOME=/home/apollo-admin/.rustup CARGO_HOME=/home/apollo-admin/.cargo RUSTUP_TOOLCHAIN=stable PATH=/home/apollo-admin/.cargo/bin:/usr/bin:/bin APOLLO_NATIVE_CONFIG={STATE}/sandboxd.toml APOLLO_NATIVE_OPERATOR_ROOT=/a64 APOLLO_NATIVE_STATE_DIR={STATE}/state APOLLO_NATIVE_CGROUP_PARENT=/sys/fs/cgroup APOLLO_NATIVE_DRIVE_DIR={STATE}/drives APOLLO_NATIVE_BASE_IMAGE={BASE} APOLLO_NATIVE_BASE_DIGEST={BASE_DIGEST} APOLLO_NATIVE_FORMATTER={FORMATTER} APOLLO_NATIVE_FORMATTER_DIGEST={FORMATTER_DIGEST} \"$PWD/$test_bin\" --ignored --exact native_firecracker_boot_exec_process_limit_file_and_pty --nocapture"],
    ]
    with tempfile.NamedTemporaryFile("w", suffix=".json") as stream:
        json.dump(commands, stream)
        stream.flush()
        return subprocess.run(
            [
                "python3",
                str(ROOT / "scripts/native_check.py"),
                "apollo-node-01",
                "--commands",
                stream.name,
                "--label",
                "native-arm64-boot",
                "--architecture",
                "aarch64",
            ],
            cwd=ROOT,
        ).returncode


if __name__ == "__main__":
    raise SystemExit(main())
