#!/usr/bin/env python3
"""Check both Linux architectures. This is never native Linux/KVM qualification."""
import os
from pathlib import Path
import subprocess
import sys
root = Path(__file__).resolve().parent.parent
environment = os.environ.copy()
for architecture in ["aarch64", "x86_64"]:
    target = architecture + "_unknown_linux_musl"
    compiler = str(root / "scripts" / ("cc-" + architecture + "-linux-musl"))
    environment["CC_" + target] = compiler
    environment["AR_" + target] = str(root / "scripts" / "ar-zig")
    environment["CARGO_TARGET_" + target.upper() + "_LINKER"] = compiler
command = ["cargo", "check", "--locked", "--workspace", "--all-targets", "--target", "aarch64-unknown-linux-musl", "--target", "x86_64-unknown-linux-musl"]
raise SystemExit(subprocess.run(command, cwd=root, env=environment).returncode)
