#!/usr/bin/env python3
"""Record exact non-secret verification commands, outputs, exits, and local host evidence."""
import datetime
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import uuid
from revision import evidence

ROOT = Path(__file__).resolve().parent.parent


def probe(command):
    try:
        result = subprocess.run(command, text=True, capture_output=True, timeout=10)
        return result.stdout.strip() if result.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired):
        return None


def main():
    command = sys.argv[1:]
    if not command:
        raise SystemExit("usage: python3 scripts/check.py COMMAND [ARG ...]")
    folder = ROOT / "qualification" / "local"
    folder.mkdir(parents=True, exist_ok=True)
    started = datetime.datetime.now(datetime.timezone.utc)
    tag = started.strftime("%Y%m%dT%H%M%S%fZ") + "-" + uuid.uuid4().hex
    output = folder / (tag + ".log")
    manifest = folder / (tag + ".sources.sha256")
    inputs = evidence(manifest)
    with output.open("x") as stream:
        result = subprocess.run(command, cwd=ROOT, stdout=stream, stderr=subprocess.STDOUT)
    with output.open("rb") as stream:
        size = output.stat().st_size
        if size > 32768:
            stream.seek(size - 32768)
            print("Display truncated; complete output retained in", output)
        print(stream.read().decode("utf-8", errors="replace"), end="")
    record = {
        "started_at": started.isoformat(), "command": command, "exit": result.returncode,
        "host_os": platform.platform(), "kernel": platform.release(),
        "cpu": probe(["sysctl", "-n", "machdep.cpu.brand_string"]) if sys.platform == "darwin" else platform.processor(),
        "architecture": platform.machine(), "rust": probe(["rustc", "--version"]),
        "cargo": probe(["cargo", "--version"]), "output": str(output.relative_to(ROOT)),
        "firecracker_version": None, "firecracker_digest": None,
        "jailer_version": None, "jailer_digest": None,
        "kernel_profile_digest": None, "guest_agent_digest": None,
        "runtime_artifacts_qualified": False,
        **inputs,
        "source_manifest": str(manifest.relative_to(ROOT)),
        "source_changed_during_command": inputs["executable_inputs_sha256"] != evidence()["executable_inputs_sha256"],
    }
    with (folder / "commands.jsonl").open("a") as stream:
        stream.write(json.dumps(record, sort_keys=True) + "\n")
    print(json.dumps({"command": command, "exit": result.returncode, "evidence": str(output)}))
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
