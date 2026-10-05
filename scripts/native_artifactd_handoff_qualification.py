#!/usr/bin/env python3
"""Run the isolated Artifactd-to-sandboxd prepared-image handoff on native Linux."""
import json
import subprocess
import tempfile
from pathlib import Path

from revision import ROOT


def main() -> int:
    hosts = (("tihan-apollo", "x86_64"), ("apollo-node-01", "aarch64"))
    status = 0
    for host, architecture in hosts:
        commands = [["sudo", "-n", "python3", "scripts/run_native_artifactd_handoff.py"]]
        with tempfile.NamedTemporaryFile("w", suffix=".json") as stream:
            json.dump(commands, stream)
            stream.flush()
            result = subprocess.run(
                ["python3", str(ROOT / "scripts/native_check.py"), host,
                 "--commands", stream.name,
                 "--label", "native-artifactd-handoff-" + architecture,
                 "--architecture", architecture],
                cwd=ROOT,
            )
            status = status or result.returncode
            if result.returncode:
                break
    return status


if __name__ == "__main__":
    raise SystemExit(main())
