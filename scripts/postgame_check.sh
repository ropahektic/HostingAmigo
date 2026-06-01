#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PYTHONPATH="${ROOT}/src"
CAPTURES="${ROOT}/captures"
if [[ $# -ge 1 ]]; then
  CAP="$1"
else
  CAP="$(ls -t "${CAPTURES}"/*.jsonl 2>/dev/null | head -1)"
fi
if [[ -z "${CAP:-}" || ! -f "$CAP" ]]; then
  echo "No capture under ${CAPTURES}" >&2
  exit 1
fi
echo "=== postgame_check ==="
echo "capture: $CAP"
echo
python3 - "$CAP" <<'PY'
import json, sys
from pathlib import Path
path = Path(sys.argv[1])
rows = [json.loads(l) for l in path.read_text().splitlines() if l.strip()]
c2_in = [
    r for r in rows
    if r.get("type") == "packet" and r.get("channel") == 2 and r.get("direction") == "in"
]
bodies = [
    bytes.fromhex(r.get("ws_payload_hex") or r.get("body_hex") or "")
    for r in c2_in
]
game_frames = sum(
    1 for b in bodies if b and b != b"\x40\x06\x00" and not b.startswith(b"\xc0\x0d")
)
first_400600 = next((i for i, b in enumerate(bodies) if b == b"\x40\x06\x00"), None)
print(f"c2_in_frames: {len(c2_in)}  gameplay-ish bodies: {game_frames}")
if first_400600 is not None:
    print(f"first 400600 at inbound index: {first_400600}")
    if first_400600 < 30 or game_frames < 15:
        print("WARNING: likely EARLY endgame (turn-1 style) — poor RE sample")
else:
    print("no 400600 sentinel in capture")
w = next((r for r in reversed(rows) if r.get("type") == "winner_inferred"), None)
if w:
    print(f"winner_inferred: slot={w.get('winner_slot')} reason={w.get('reason')}")
g = next((r for r in reversed(rows) if r.get("type") == "wire_re_gap"), None)
if g:
    print(f"wire_re_gap: {g.get('summary', g)}")
PY
echo
echo "--- gamenet_re_probe ---"
python3 "${ROOT}/scripts/gamenet_re_probe.py" "$CAP" || true
if [[ -f "${ROOT}/scripts/compare_arena_wire.py" ]]; then
  echo
  echo "--- compare_arena_wire ---"
  python3 "${ROOT}/scripts/compare_arena_wire.py" "$CAP" 2>/dev/null || true
fi
echo
echo "Done."
