#!/bin/bash
# Validate labeled rank captures against strict wire decode.
set -euo pipefail
cd "$(dirname "$0")/.."
export PYTHONPATH=src

echo "=== Wire corpus validation (strict 1020/1043) ===" >&2
python3 scripts/replay_wire_winner.py --all --compact --labels --validate --gap 2>&1 | tee /tmp/wire_corpus.log
grep -E '20260601T|vs-label' /tmp/wire_corpus.log | tail -20 || true

echo ""
echo "=== Labeled rank games only ==="
python3 - <<'PY'
import json
from pathlib import Path
import subprocess

labels = json.loads(Path("captures/result_labels.json").read_text())
rank = [e for e in labels if e.get("winner_slot") is not None and "rank" in str(e.get("capture", ""))]
fail = 0
for e in rank:
    cap = Path("captures") / e["capture"]
    if not cap.exists():
        continue
    r = subprocess.run(
        ["python3", "scripts/replay_wire_winner.py", str(cap), "--labels", "--gap"],
        capture_output=True,
        text=True,
        env={**dict(__import__("os").environ), "PYTHONPATH": "src"},
    )
    ok = r.returncode == 0
    if not ok:
        fail += 1
    print(r.stdout.strip() or r.stderr.strip())
print(f"\n--- {len(rank)} labeled rank checks, {fail} failed ---")
raise SystemExit(1 if fail else 0)
PY
