#!/usr/bin/env python3
"""Run the public daemon API lifecycle contract on the authorized x86_64 host."""
import base64
import datetime
import json
import subprocess
import tempfile
from pathlib import Path

from revision import ROOT, evidence

HOST = "tihan-apollo"
STATE = "/var/lib/apollo-sandboxd/native-api-" + datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
BASE = "/opt/apollo-sandboxd/reference-images/x86_64/ce7fe8a6c6f7ea31e5494cbafb0613f8826a32cc7e9afede04244c89a8b561d0/rootfs.ext4"
BASE_DIGEST = "ce7fe8a6c6f7ea31e5494cbafb0613f8826a32cc7e9afede04244c89a8b561d0"
FORMATTER = "/opt/apollo-sandboxd/storage-tools/14d64b707e37214aff4568470bb4d908232370684c7eff05465d78116c2c9c67/mke2fs"
FORMATTER_DIGEST = "14d64b707e37214aff4568470bb4d908232370684c7eff05465d78116c2c9c67"


def main() -> int:
    config = (ROOT / "qualification/native-x86/sandboxd.toml").read_text()
    config = config.replace('directory = "/var/lib/apollo-sandboxd"',
                            f'directory = "{STATE}/state"', 1)
    config += f'''\n[execution]\noperator_root = "/a"\ncgroup_parent = "/sys/fs/cgroup"\ndrive_directory = "{STATE}/drives"\nformatter = "{FORMATTER}"\nformatter_sha256 = "{FORMATTER_DIGEST}"\nboot_timeout_seconds = 60\nkernel_arguments = "console=ttyS0 reboot=k panic=1 pci=off"\n\n[[execution.images]]\ndigest = "sha256:{BASE_DIGEST}"\narchitecture = "x86_64"\npath = "{BASE}"\n'''
    config_b64 = base64.b64encode(config.encode()).decode()
    source_revision = evidence()["executable_inputs_sha256"]
    commands = [
        ["sudo", "-n", "install", "-d", "-m", "700", STATE, f"{STATE}/drives", f"{STATE}/state", "/a"],
        ["sudo", "-n", "python3", "-c", f"import base64,os; p='{STATE}/sandboxd.toml'; open(p,'wb').write(base64.b64decode('{config_b64}')); os.chmod(p,0o600)"],
        ["sudo", "-n", "env", "RUSTUP_HOME=/home/tihan/.rustup", "CARGO_HOME=/home/tihan/.cargo",
         f"APOLLO_NATIVE_API_CONFIG={STATE}/sandboxd.toml",
         "APOLLO_NATIVE_API_SOCKET=/run/apollo-sandboxd/sandboxd.sock",
         f"APOLLO_NATIVE_API_EVIDENCE={STATE}/evidence.log",
         f"APOLLO_NATIVE_SOURCE_REVISION={source_revision}",
         f"APOLLO_NATIVE_BASE_DIGEST={BASE_DIGEST}",
         "APOLLO_NATIVE_RUNTIME_PROFILE=fc-1-17-x86",
         "APOLLO_NATIVE_KERNEL_PROFILE=amazonlinux-microvm-x86",
         "RUSTUP_TOOLCHAIN=1.96.0", "cargo", "build", "--locked", "--bin", "apollo-sandboxd"],
        ["sudo", "-n", "env", "RUSTUP_HOME=/home/tihan/.rustup", "CARGO_HOME=/home/tihan/.cargo",
         f"APOLLO_NATIVE_API_CONFIG={STATE}/sandboxd.toml",
         "APOLLO_NATIVE_API_SOCKET=/run/apollo-sandboxd/sandboxd.sock",
         f"APOLLO_NATIVE_API_EVIDENCE={STATE}/evidence.log",
         f"APOLLO_NATIVE_SOURCE_REVISION={source_revision}",
         f"APOLLO_NATIVE_BASE_DIGEST={BASE_DIGEST}",
         "APOLLO_NATIVE_RUNTIME_PROFILE=fc-1-17-x86",
         "APOLLO_NATIVE_KERNEL_PROFILE=amazonlinux-microvm-x86",
         "RUSTUP_TOOLCHAIN=1.96.0", "cargo", "test", "--locked", "--test",
         "native_api_contract", "--", "--ignored", "--nocapture"],
    ]
    with tempfile.NamedTemporaryFile("w", suffix=".json") as stream:
        json.dump(commands, stream)
        stream.flush()
        return subprocess.run(
            ["python3", str(ROOT / "scripts/native_check.py"), HOST,
             "--commands", stream.name, "--label", "native-api"],
            cwd=ROOT,
        ).returncode


if __name__ == "__main__":
    raise SystemExit(main())
