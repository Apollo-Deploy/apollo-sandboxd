#!/usr/bin/env python3
"""Build a pinned source snapshot on an authorized native Linux SSH host."""
import argparse
import datetime
import hashlib
import io
import json
import shlex
import subprocess
import tarfile
from pathlib import Path

from revision import ARTIFACTD_PROTOCOL, ROOT, evidence

REMOTE = r'''
import hashlib, io, json, os, pathlib, platform, signal, subprocess, sys, tarfile, tempfile
fixture = pathlib.Path(tempfile.mkdtemp(prefix="sandboxd-native-check.", dir="/var/tmp"))
fixture.chmod(0o700)
# SSH non-login commands may skip the account's shell profile. Include the
# standard per-user Rust toolchain bin directory for both probes and builds.
cargo_bin = pathlib.Path.home() / ".cargo" / "bin"
if cargo_bin.is_dir():
    os.environ["PATH"] = str(cargo_bin) + os.pathsep + os.environ.get("PATH", "")
archive = sys.stdin.buffer.read(16 * 1024 * 1024 + 1)
if len(archive) > 16 * 1024 * 1024:
    raise SystemExit("source archive exceeds bound")
with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as stream:
    entries = stream.getmembers()
    if len(entries) > 2048 or any(not entry.isfile() or entry.size > 8 * 1024 * 1024
        or pathlib.PurePosixPath(entry.name).is_absolute()
        or ".." in pathlib.PurePosixPath(entry.name).parts for entry in entries):
        raise SystemExit("unsafe source archive")
    if len({entry.name for entry in entries}) != len(entries):
        raise SystemExit("duplicate source archive member")
    stream.extractall(fixture, filter="data")
manifest = (fixture / "sources.sha256").read_bytes()
for line in manifest.decode().splitlines():
    digest, name = line.split("  ", 1)
    source = fixture / name
    if name.startswith("artifactd-protocol/"):
        source = fixture / "apollo-artifactd" / "crates" / "artifactd-protocol" / name.removeprefix("artifactd-protocol/")
    else:
        source = fixture / "apollo-sandboxd" / name
    if hashlib.sha256(source.read_bytes()).hexdigest() != digest:
        raise SystemExit("source digest mismatch")
def probe(argv):
    result = subprocess.run(argv, text=True, capture_output=True, timeout=10)
    return {"command": argv, "exit": result.returncode, "output": result.stdout.strip()}
record = {
    "fixture": str(fixture), "source_sha256": hashlib.sha256(manifest).hexdigest(),
    "cargo_lock_sha256": hashlib.sha256((fixture / "apollo-sandboxd" / "Cargo.lock").read_bytes()).hexdigest(),
    "architecture": platform.machine(), "kernel": platform.release(),
    "os_release": pathlib.Path("/etc/os-release").read_text(),
    "cpu": probe(["lscpu"]), "rust": probe(["rustc", "--version", "--verbose"]),
    "cargo": probe(["cargo", "--version"]), "commands": [], "binary_sha256": {}}
expected_architecture = (fixture / "native-architecture").read_text().strip()
if platform.system() != "Linux" or platform.machine() != expected_architecture:
    raise SystemExit("native %s Linux required" % expected_architecture)
commands = json.loads((fixture / "commands.json").read_text())
environment = dict(os.environ, CARGO_BUILD_JOBS="2", CARGO_TARGET_DIR=str(fixture / "target"))
failed = False
for index, argv in enumerate(commands):
    output = fixture / ("command-%02d.log" % index)
    with output.open("wb") as log:
        try:
            process = subprocess.Popen(argv, cwd=fixture / "apollo-sandboxd", env=environment, stdout=log,
                stderr=subprocess.STDOUT, start_new_session=True)
            code = process.wait(timeout=600)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            code = 124
    record["commands"].append({"command": argv, "exit": code, "output": output.name})
    failed |= code != 0
    print(json.dumps({"command": argv, "exit": code, "fixture": str(fixture)}), flush=True)
    if code != 0:
        print(output.read_text(errors="replace")[-8192:], flush=True)
for path in (fixture / "target").rglob("*"):
    if path.is_file() and path.stat().st_mode & 0o111:
        with path.open("rb") as stream:
            if stream.read(4) != b"\x7fELF":
                continue
        record["binary_sha256"][str(path.relative_to(fixture))] = hashlib.sha256(path.read_bytes()).hexdigest()
# Collect the qualification runner's bounded private strace output.  The
# runner invokes strace under sudo, so copy only the known owned prefix via
# sudo before archiving; missing files are retained as an explicit probe
# result instead of silently disappearing.
trace_prefix = pathlib.Path(
    "/var/lib/apollo-sandboxd/native-arm64/strace"
    if expected_architecture == "aarch64"
    else "/var/lib/apollo-sandboxd/native-boot/strace"
)
trace_result = {"prefix": str(trace_prefix), "files": [], "bytes": 0, "error": None}
listed = subprocess.run(
    ["sudo", "-n", "find", str(trace_prefix.parent), "-maxdepth", "1",
     "-type", "f", "-name", trace_prefix.name + "*", "-printf", "%T@ %p\n"],
    capture_output=True, text=True, timeout=10,
)
if listed.returncode != 0:
    trace_result["error"] = listed.stderr.strip()[-512:] or "trace listing failed"
else:
    recent = sorted(listed.stdout.splitlines(), reverse=True)[:256]
    for raw_source in recent:
        _, raw_path = raw_source.split(" ", 1)
        source = pathlib.Path(raw_path)
        if len(trace_result["files"]) >= 256:
            trace_result["error"] = "trace file bound exceeded"
            break
        stat = subprocess.run(["sudo", "-n", "stat", "-c", "%s", "--", str(source)],
                              capture_output=True, text=True, timeout=10)
        try:
            source_size = int(stat.stdout.strip())
        except ValueError:
            source_size = -1
        if source_size < 0 or trace_result["bytes"] + source_size > 8 * 1024 * 1024:
            trace_result["error"] = "trace byte bound exceeded"
            break
        target = fixture / ("native-" + source.name)
        copied = subprocess.run(["sudo", "-n", "cp", "--", str(source), str(target)],
                                capture_output=True, text=True, timeout=10)
        if copied.returncode != 0:
            trace_result["error"] = copied.stderr.strip()[-512:] or "trace copy failed"
            break
        owned = subprocess.run(["sudo", "-n", "chown", f"{os.getuid()}:{os.getgid()}", "--", str(target)],
                               capture_output=True, text=True, timeout=10)
        if owned.returncode != 0:
            trace_result["error"] = owned.stderr.strip()[-512:] or "trace ownership transfer failed"
            break
        target.chmod(0o600)
        trace_result["files"].append(target.name)
        trace_result["bytes"] += source_size
record["strace"] = trace_result
(fixture / "provenance.json").write_text(json.dumps(record, indent=2) + "\n")
print(json.dumps({"fixture": str(fixture), "failed": failed, "strace": trace_result}), flush=True)
raise SystemExit(1 if failed else 0)
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host")
    parser.add_argument("--commands", required=True, type=Path,
                        help="JSON array of exact command argument arrays")
    parser.add_argument("--label", default="native-x86")
    parser.add_argument("--architecture", choices=("x86_64", "aarch64"), default="x86_64")
    args = parser.parse_args()
    if not args.label.replace("-", "").replace("_", "").isalnum():
        raise SystemExit("invalid evidence label")
    commands = json.loads(args.commands.read_text())
    if not isinstance(commands, list) or not 1 <= len(commands) <= 16 or any(
        not isinstance(command, list) or not command or
        any(not isinstance(value, str) or "\x00" in value for value in command)
        for command in commands
    ):
        raise SystemExit("invalid command argument arrays")
    tag = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    folder = ROOT / "qualification" / args.label / tag
    folder.mkdir(parents=True, exist_ok=False)
    manifest = folder / "sources.sha256"
    inputs = evidence(manifest)
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode="w:gz") as stream:
        for line in manifest.read_text().splitlines():
            _, name = line.split("  ", 1)
            if name.startswith("artifactd-protocol/"):
                relative = name.removeprefix("artifactd-protocol/")
                source = ARTIFACTD_PROTOCOL / relative
                arcname = "apollo-artifactd/crates/artifactd-protocol/" + relative
            else:
                source = ROOT / name
                arcname = "apollo-sandboxd/" + name
            stream.add(source, arcname=arcname, recursive=False)
        for name, data in (("sources.sha256", manifest.read_bytes()),
                           ("commands.json", json.dumps(commands).encode()),
                           ("native-architecture", args.architecture.encode())):
            member = tarfile.TarInfo(name)
            member.size, member.mode = len(data), 0o600
            stream.addfile(member, io.BytesIO(data))
    argv = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", args.host,
            "python3 -c " + shlex.quote(REMOTE)]
    result = subprocess.run(argv, input=archive.getvalue(), capture_output=True)
    (folder / "remote-run.log").write_bytes(result.stdout + result.stderr)
    print(result.stdout.decode(errors="replace"), end="")
    records = [json.loads(line) for line in result.stdout.decode().splitlines() if line.startswith("{")]
    fixture = records[-1]["fixture"] if records else None
    if fixture and fixture.startswith("/var/tmp/sandboxd-native-check.") and ".." not in fixture:
        command = "tar -czf - -C " + shlex.quote(fixture) + " provenance.json sources.sha256 commands.json "
        command += " ".join("command-%02d.log" % index for index in range(len(commands)))
        trace_names = records[-1].get("strace", {}).get("files", []) if records else []
        command += " " + " ".join(shlex.quote(name) for name in trace_names)
        collected = subprocess.run(argv[:-1] + [command], capture_output=True)
        if collected.returncode != 0:
            raise SystemExit("native evidence download failed: " + collected.stderr.decode(errors="replace")[-1000:])
        with tarfile.open(fileobj=io.BytesIO(collected.stdout), mode="r:gz") as stream:
            stream.extractall(folder, filter="data")
    receipt = {**inputs, "ssh_host": args.host, "fixture": fixture, "exit": result.returncode,
               "commands": commands, "source_changed_during_command":
               inputs["executable_inputs_sha256"] != evidence()["executable_inputs_sha256"]}
    (folder / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps({"evidence": str(folder), "exit": result.returncode}))
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
