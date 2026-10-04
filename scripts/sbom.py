#!/usr/bin/env python3
"""Emit a CycloneDX JSON dependency inventory from the locked Cargo resolution."""
import json
from pathlib import Path
import subprocess
import uuid

ROOT = Path(__file__).resolve().parent.parent
metadata = json.loads(subprocess.run(["cargo", "metadata", "--locked", "--format-version", "1"],
                                    cwd=ROOT, check=True, capture_output=True, text=True).stdout)
components = []
references = {}
for package in metadata["packages"]:
    ref = "pkg:cargo/" + package["name"] + "@" + package["version"]
    references[package["id"]] = ref
    component = {"type": "library", "bom-ref": ref, "name": package["name"],
                 "version": package["version"], "purl": ref}
    if package["license"]:
        component["licenses"] = [{"expression": package["license"]}]
    components.append(component)
bom = {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
       "serialNumber": "urn:uuid:" + str(uuid.uuid4()), "components": components,
       "dependencies": [{"ref": references[node["id"]],
                          "dependsOn": sorted({references[dep["pkg"]] for dep in node["deps"]})}
                         for node in metadata["resolve"]["nodes"]]}
folder = ROOT / "qualification" / "local"
folder.mkdir(parents=True, exist_ok=True)
path = folder / "sbom.cdx.json"
path.write_text(json.dumps(bom, indent=2) + "\n")
print(json.dumps({"artifact": str(path), "components": len(components)}))
