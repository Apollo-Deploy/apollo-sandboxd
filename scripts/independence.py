#!/usr/bin/env python3
"""Verify resolved dependency ownership; inspect the dependency graph, not source spellings."""
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parent.parent
LOCAL = {"apollo-sandboxd", "apollo-sandbox-guest", "sandboxd-protocol", "guest-protocol", "firecracker-api"}


def main():
    result = subprocess.run(["cargo", "metadata", "--locked", "--format-version", "1"],
                            cwd=ROOT, check=True, capture_output=True, text=True)
    metadata = json.loads(result.stdout)
    packages = metadata["packages"]
    for package in packages:
        source = package["source"]
        if source is None:
            path = Path(package["manifest_path"]).resolve()
            if package["name"] not in LOCAL or not path.is_relative_to(ROOT):
                raise SystemExit("foreign local implementation dependency")
        elif not source.startswith("registry+"):
            raise SystemExit("non-registry dependency source rejected")
        if package["name"].startswith("apollo-") and package["name"] not in {"apollo-sandboxd", "apollo-sandbox-guest"}:
            raise SystemExit("another Apollo package is in the dependency graph")
    print(json.dumps({"passed": True, "packages": len(packages), "workspace": sorted(LOCAL),
                      "git_dependencies": 0, "foreign_apollo_dependencies": 0}, sort_keys=True))


if __name__ == "__main__":
    main()
