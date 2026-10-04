#!/usr/bin/env python3
"""Hash executable inputs, including untracked files, without self-referential reports."""
import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def evidence(manifest=None):
    paths = set()
    for name in ("Cargo.toml", "Cargo.lock", "config.example.toml"):
        paths.add(ROOT / name)
    for folder in ("src", "crates", "guest-agent", "tests", "scripts", "packaging"):
        for path in (ROOT / folder).rglob("*"):
            if not {"target", "__pycache__"}.intersection(path.relative_to(ROOT).parts) and path.is_file():
                paths.add(path)
    for name in ("Cargo.toml", "Cargo.lock"):
        paths.add(ROOT / "fuzz" / name)
    paths.update((ROOT / "fuzz" / "fuzz_targets").glob("*.rs"))
    lines = []
    for path in sorted(paths):
        if path.is_symlink():
            raise ValueError("executable input symlinks are not supported")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        lines.append(f"{digest}  {path.relative_to(ROOT).as_posix()}\n")
    encoded = "".join(lines).encode()
    if manifest is not None:
        Path(manifest).write_bytes(encoded)
    return {"executable_inputs_sha256": hashlib.sha256(encoded).hexdigest(),
            "input_files": len(lines),
            "scope": "src,crates,guest-agent,tests,scripts,packaging,root Cargo/config,fuzz manifests/targets; excludes .git,docs,build output,generated corpus,evidence"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path)
    args = parser.parse_args()
    print(json.dumps(evidence(args.manifest), sort_keys=True))
