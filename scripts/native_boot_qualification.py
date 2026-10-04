#!/usr/bin/env python3
"""Run the real jailed x86_64 Firecracker boot contract on the pinned host."""
import base64
import json
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONFIG = (ROOT / "qualification/native-x86/sandboxd.toml").read_bytes()

def main() -> int:
    host = "tihan-apollo"
    config_b64 = base64.b64encode(CONFIG).decode()
    commands = [
        ["sudo", "-n", "install", "-d", "-m", "700", "/var/lib/apollo-sandboxd/native-boot", "/var/lib/apollo-sandboxd/native-boot/drives", "/var/lib/apollo-sandboxd/native-boot/state", "/a"],
        ["sudo", "-n", "find", "/var/lib/apollo-sandboxd/native-boot", "-maxdepth", "1", "-type", "f", "-name", "strace*", "-delete"],
        ["sudo", "-n", "python3", "-c", f"import base64; p='/var/lib/apollo-sandboxd/native-boot/sandboxd.toml'; open(p,'wb').write(base64.b64decode('{config_b64}'))"],
        ["sudo", "-n", "strace", "-ff", "-tt", "-s", "512", "-e", "trace=process,execve,connect,bind,listen,openat,write", "-o", "/var/lib/apollo-sandboxd/native-boot/strace", "env", "HOME=/home/tihan", "RUSTUP_HOME=/home/tihan/.rustup", "CARGO_HOME=/home/tihan/.cargo", "RUSTUP_TOOLCHAIN=1.96.0", "APOLLO_NATIVE_CONFIG=/var/lib/apollo-sandboxd/native-boot/sandboxd.toml", "APOLLO_NATIVE_OPERATOR_ROOT=/a", "APOLLO_NATIVE_STATE_DIR=/var/lib/apollo-sandboxd/native-boot/state", "APOLLO_NATIVE_CGROUP_PARENT=/sys/fs/cgroup", "APOLLO_NATIVE_DRIVE_DIR=/var/lib/apollo-sandboxd/native-boot/drives", "APOLLO_NATIVE_BASE_IMAGE=/opt/apollo-sandboxd/reference-images/x86_64/ce7fe8a6c6f7ea31e5494cbafb0613f8826a32cc7e9afede04244c89a8b561d0/rootfs.ext4", "APOLLO_NATIVE_BASE_DIGEST=ce7fe8a6c6f7ea31e5494cbafb0613f8826a32cc7e9afede04244c89a8b561d0", "APOLLO_NATIVE_FORMATTER=/opt/apollo-sandboxd/storage-tools/14d64b707e37214aff4568470bb4d908232370684c7eff05465d78116c2c9c67/mke2fs", "APOLLO_NATIVE_FORMATTER_DIGEST=14d64b707e37214aff4568470bb4d908232370684c7eff05465d78116c2c9c67", "cargo", "test", "--locked", "--test", "native_boot_contract", "--", "--ignored", "--nocapture"],
    ]
    with tempfile.NamedTemporaryFile("w", suffix=".json") as stream:
        json.dump(commands, stream)
        stream.flush()
        return subprocess.run(["python3", str(ROOT / "scripts/native_check.py"), host, "--commands", stream.name, "--label", "native-boot"], cwd=ROOT).returncode

if __name__ == "__main__":
    raise SystemExit(main())
