#!/usr/bin/env python3
"""Scan rank captures for wire RE corpus flags vs inferred winner."""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from wormnetbot.wa_task_stream import (
    announced_result_from_bodies,
    summarize_wire_re_gap,
)

CAPTURES = Path(__file__).resolve().parents[1] / "captures"


def load_rows(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def human_slots(rows: list[dict]) -> set[int]:
    slots: set[int] = set()
    for row in rows:
        if row.get("type") != "lobby_snapshot":
            continue
        for team in row.get("teams", []):
            slot = int(team.get("slot", 0))
            name = str(team.get("name", ""))
            if slot > 0 and not name.endswith("'s team"):
                slots.add(slot)
    return slots


def endgame_bodies(rows: list[dict]) -> list[bytes]:
    bodies: list[bytes] = []
    for row in rows:
        if row.get("type") != "packet":
            continue
        if row.get("channel") != 2 or row.get("direction") != "in":
            continue
        body_hex = row.get("ws_payload_hex") or row.get("body_hex")
        if body_hex:
            bodies.append(bytes.fromhex(body_hex))
    return bodies


def winner_inferred_row(rows: list[dict]) -> dict | None:
    for row in reversed(rows):
        if row.get("type") == "winner_inferred":
            return row
    return None


def main() -> int:
    paths = sorted(CAPTURES.glob("*rank*.jsonl"))
    if not paths:
        print("no *rank*.jsonl under", CAPTURES, file=sys.stderr)
        return 1

    hdr = (
        f"{'file':<42} {'0c14':>4} {'401e':>4} "
        f"{'winner_inferred':<22} {'wire_winner':>11}"
    )
    print(hdr)
    print("-" * len(hdr))

    n_0c14 = 0
    for path in paths:
        rows = load_rows(path)
        bodies = endgame_bodies(rows)
        gap = summarize_wire_re_gap(bodies)
        slots = human_slots(rows)
        wire = (
            announced_result_from_bodies(bodies, slots)
            if len(slots) >= 2
            else None
        )
        wi = winner_inferred_row(rows)
        wi_reason = wi.get("reason", "-") if wi else "-"
        wire_w = wire.winner_slot if wire else "-"
        if gap["has_0c14"]:
            n_0c14 += 1
        print(
            f"{path.name:<42} "
            f"{str(gap['has_0c14']):>4} {str(gap['has_401e']):>4} "
            f"{wi_reason:<22} {str(wire_w):>11}"
        )

    print(f"\nSummary: {n_0c14}/{len(paths)} captures have framed 0c14 in C2 bodies")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
