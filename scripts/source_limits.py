#!/usr/bin/env python3
"""Apply the requested hard Rust source ceiling; include colocated tests in source counts."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
files = [path for pattern in ("src/**/*.rs", "guest-agent/src/**/*.rs", "crates/*/src/**/*.rs", "crates/*/tests/**/*.rs", "tests/**/*.rs", "fuzz/fuzz_targets/*.rs")
         for path in ROOT.glob(pattern)]
counts = {str(path.relative_to(ROOT)): len(path.read_text().splitlines()) for path in files}
large = {path: lines for path, lines in counts.items() if lines > 500}
print(json.dumps({"files": len(files), "largest": max(counts.values(), default=0),
                  "soft_threshold": {p: n for p, n in counts.items() if n > 350},
                  "hard_violations": large}, sort_keys=True))
raise SystemExit(bool(large))
