#!/usr/bin/env python3
"""
For each labeled capture, scan the **endgame window** (inbound ch2 packets before
``400600`` — same as ``analyze_result_frames.endgame_window``) for raw bytes
``0x14`` and ``0x2b`` (hypothetical ``v`` where ``TaskMessageType = v + 1000`` →
1020 / 1043 per ``wa_serialization.py``).

Output: per-file summary + aggregated counts by **rel** (distance from sentinel).
Does **not** prove semantics — only whether hits cluster near game end.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))

import analyze_result_frames as ar  # noqa: E402


def offsets_of(body: bytes, needle: int) -> list[int]:
    b = bytes([needle])
    out: list[int] = []
    i = 0
    while True:
        j = body.find(b, i)
        if j < 0:
            break
        out.append(j)
        i = j + 1
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--captures-dir",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "captures",
    )
    ap.add_argument(
        "--labels",
        type=Path,
        default=_SCRIPT_DIR / "result_labels.json",
    )
    ap.add_argument("--window", type=int, default=24)
    args = ap.parse_args()

    labels: dict[str, dict] = json.loads(args.labels.read_text(encoding="utf-8"))
    needles = (
        (0x14, "v=20→type1020"),
        (0x2B, "v=43→type1043"),
    )

    by_rel: Counter[tuple[int, str]] = Counter()
    by_slot_rel: defaultdict[str, Counter[tuple[int, str]]] = defaultdict(Counter)
    n_labeled = 0
    n_empty_window = 0

    for path in sorted(args.captures_dir.glob("*.jsonl")):
        info = labels.get(path.name)
        if not info:
            continue
        n_labeled += 1
        slot = int(info["winner_slot"])
        slot_key = f"slot{slot}"
        records = ar.load_capture(path)
        packets = ar.endgame_window(records, args.window)
        if not packets:
            n_empty_window += 1
            print(f"\n== {path.name} {slot_key} ==")
            print("  <empty endgame window (no inbound ch2 packets)>")
            continue

        print(f"\n== {path.name} {slot_key} winner={info.get('winner_team')} ==")
        n = len(packets)
        for i, rec in enumerate(packets):
            rel = i - n
            body = bytes.fromhex(str(rec["body_hex"]))
            fam = ar.packet_family(str(rec["body_hex"]))
            parts: list[str] = []
            for val, name in needles:
                pos = offsets_of(body, val)
                if pos:
                    parts.append(f"{name}@{pos}")
                    for p in pos:
                        by_rel[(rel, name)] += 1
                        by_slot_rel[slot_key][(rel, name)] += 1
            extra = f"  {'; '.join(parts)}" if parts else ""
            print(
                f"  rel={rel:3} frame={rec.get('frame')} len={len(body):4} fam={fam[:28]}{extra}"
            )

    print("\n== aggregate: hits by (rel_index, needle) across labeled captures ==")
    for (rel, name), c in sorted(by_rel.items(), key=lambda x: (x[0][0], x[0][1])):
        print(f"  rel={rel:3} {name:18} total={c}")

    print("\n== aggregate by winner slot (same keys) ==")
    for sk in sorted(by_slot_rel):
        print(f"  --- {sk} ---")
        for (rel, name), c in sorted(by_slot_rel[sk].items(), key=lambda x: (x[0][0], x[0][1])):
            print(f"    rel={rel:3} {name:18} n={c}")

    print(f"\n(labeled captures scanned: {n_labeled}; empty endgame window: {n_empty_window})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
