#!/usr/bin/env python3
"""Offline probe: which C2 bodies contain strict task-1020/1043 decodable bytes."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from wormnetbot.wa_gamenet_containers import extract_length_chunk_payloads, extract_msg_save_stream
from wormnetbot.wa_task_stream import (
    announced_result_from_bodies,
    parse_surrender_announcements,
    parse_win_announcements,
)

CAPTURES = Path(__file__).resolve().parents[1] / "captures"


def load_rows(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def slot_map(rows: list[dict]) -> dict[str, int]:
    out: dict[str, int] = {}
    for row in rows:
        if row.get("type") != "lobby_snapshot":
            continue
        for team in row.get("teams", []):
            nick = team.get("owner_nickname")
            slot = team.get("slot", 0)
            if nick and slot > 0:
                out[str(nick)] = int(slot)
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("jsonl", type=Path, nargs="?", help="Capture file (default: latest)")
    ap.add_argument("--endgame-only", action="store_true", help="Only frames before first 400600")
    args = ap.parse_args()

    if args.jsonl:
        path = args.jsonl
    else:
        candidates = sorted(CAPTURES.glob("*.jsonl"), key=lambda p: p.stat().st_mtime)
        if not candidates:
            print("no captures", file=sys.stderr)
            return 1
        path = candidates[-1]

    rows = load_rows(path)
    slots = slot_map(rows)
    human_slots = {s for s in slots.values() if s > 0}
    bodies: list[bytes] = []
    for row in rows:
        if row.get("type") != "packet" or row.get("channel") != 2:
            continue
        if row.get("direction") != "in":
            continue
        bodies.append(bytes.fromhex(row.get("ws_payload_hex") or row.get("body_hex") or ""))

    if args.endgame_only:
        trimmed: list[bytes] = []
        for body in bodies:
            trimmed.append(body)
            if body == b"\x40\x06\x00":
                break
        bodies = trimmed

    print(f"capture: {path.name} human_slots={sorted(human_slots)} bodies={len(bodies)}")

    any_win = any(parse_win_announcements(b) for b in bodies)
    any_sur = any(parse_surrender_announcements(b) for b in bodies)
    print(f"  parse_win anywhere: {any_win}")
    print(f"  parse_surrender anywhere: {any_sur}")

    for body in bodies:
        if body.startswith((b"\x5c\x1f", b"\x40\x1e", b"\x44\x02")):
            chunks = extract_length_chunk_payloads(body)
            if chunks:
                print(f"  container {body[:4].hex()} chunks={[c.hex() for c in chunks]}")

    if len(human_slots) >= 2:
        result = announced_result_from_bodies(bodies, human_slots)
        print(f"  announced_result: {result}")

    # Raw byte search (diagnostic only — not used for inference)
    for needle, name in [(b"\x0c\x14", "0c14"), (b"\x0c\x2b", "0c2b"), (b"\x2b", "2b")]:
        hits = 0
        for body in bodies:
            if needle in body:
                hits += 1
        print(f"  raw contains {name}: {hits} bodies")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
