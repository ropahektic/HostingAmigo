#!/usr/bin/env python3
"""Research report: Ghidra-backed endgame announcements vs labeled captures.

Runs corpus scan for ``0c14`` / ``0c2b`` / aligned ``2b`` and compares to
``captures/result_labels.json``.  Does not use ladder heuristics.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from wormnetbot.wa_task_stream import (
    announced_result_from_bodies,
    count_400204_ladder_frames,
    map_team_index_to_slot,
    parse_surrender_announcements,
    parse_win_announcements,
    _scan_framed_tag,
    WIRE_TAG_SURRENDER,
    WIRE_TAG_WIN,
)

CAPTURES = ROOT / "captures"
LABELS = CAPTURES / "result_labels.json"


def load_rows(path: Path) -> list[dict]:
    text = path.read_bytes().decode("utf-8", errors="replace")
    out: list[dict] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict):
            out.append(row)
    return out


def roster_slots(rows: list[dict]) -> dict[str, int]:
    slots: dict[str, int] = {}
    for row in rows:
        if row.get("type") != "lobby_snapshot":
            continue
        for player in row.get("players", []):
            slot = player.get("team_slot", 0)
            if slot > 0:
                slots[player["nickname"]] = slot
    return slots


def corpus_framed_hits() -> tuple[list[tuple], list[tuple]]:
    wins: list[tuple] = []
    surs: list[tuple] = []
    for path in sorted(CAPTURES.glob("*.jsonl")):
        for row in load_rows(path):
            if row.get("channel") != 2 or row.get("direction") != "in":
                continue
            hx = row.get("ws_payload_hex") or row.get("body_hex")
            if not hx:
                continue
            try:
                body = bytes.fromhex(hx)
            except ValueError:
                continue
            nick = row.get("nickname") or "?"
            for off, idx in _scan_framed_tag(body, WIRE_TAG_WIN):
                wins.append((path.name, nick, off, idx, body[off : off + 3].hex()))
            for off, idx in _scan_framed_tag(body, WIRE_TAG_SURRENDER):
                surs.append((path.name, nick, off, idx, body[off : off + 3].hex()))
    return wins, surs


def analyze_label(entry: dict) -> dict:
    path = CAPTURES / entry["capture"]
    rows = load_rows(path)
    slots = roster_slots(rows)
    valid = {slots[entry["winner"]], slots[entry["loser"]]}
    bodies: list[bytes] = []
    ladder: dict[int, int] = {}
    first_sentinel: int | None = None
    for row in rows:
        if row.get("channel") != 2 or row.get("direction") != "in":
            continue
        if row.get("body_hex") == "400600" and first_sentinel is None:
            first_sentinel = slots.get(row.get("nickname", ""))
        hx = row.get("body_hex")
        if not hx:
            continue
        body = bytes.fromhex(hx)
        bodies.append(body)
        nick = row.get("nickname")
        slot = slots.get(nick or "")
        if slot:
            n = count_400204_ladder_frames(body)
            if n:
                ladder[slot] = ladder.get(slot, 0) + n

    win_hits = []
    sur_hits = []
    for body in bodies:
        win_hits.extend(parse_win_announcements(body))
        for off, idx in parse_surrender_announcements(body):
            if map_team_index_to_slot(idx, valid) is not None:
                sur_hits.append((off, idx))

    strict = announced_result_from_bodies(bodies, valid, allow_ladder_fallback=False)
    heuristic = announced_result_from_bodies(
        bodies,
        valid,
        ladder_counts=ladder or None,
        first_sentinel_slot=first_sentinel,
        allow_ladder_fallback=True,
    )

    return {
        "capture": entry["capture"],
        "winner": entry["winner"],
        "loser": entry["loser"],
        "winner_slot": slots.get(entry["winner"]),
        "loser_slot": slots.get(entry["loser"]),
        "win_hits": win_hits,
        "sur_hits": sur_hits,
        "ladder": ladder,
        "first_sentinel": first_sentinel,
        "strict_ok": strict is not None and strict.winner_slot == slots.get(entry["winner"]),
        "strict_reason": strict.reason if strict else None,
        "strict_slot": strict.winner_slot if strict else None,
        "heuristic_ok": heuristic is not None and heuristic.winner_slot == slots.get(entry["winner"]),
        "heuristic_reason": heuristic.reason if heuristic else None,
        "heuristic_slot": heuristic.winner_slot if heuristic else None,
    }


def main() -> int:
    print("=" * 72)
    print("WA endgame research matrix (Ghidra decode vs captures)")
    print("=" * 72)

    wins, surs = corpus_framed_hits()
    print(f"\nCorpus framed 0c14 (task-1020): {len(wins)}")
    for row in wins:
        print(f"  {row[0]:40} {row[1]:10} off={row[2]} idx={row[3]} raw={row[4]}")
    print(f"\nCorpus framed 0c2b (task-1043): {len(surs)}")
    for row in surs:
        print(f"  {row[0]:40} {row[1]:10} off={row[2]} idx={row[3]} raw={row[4]}")

    if not LABELS.is_file():
        print("\n(no result_labels.json)")
        return 0

    labels = json.loads(LABELS.read_text())
    print("\nLabeled games (strict decode = task-1020/1043 only):")
    print(f"{'capture':<36} {'GT':<8} {'strict':<18} {'heuristic':<18} ladder")
    strict_pass = heuristic_pass = 0
    for entry in labels:
        r = analyze_label(entry)
        strict_pass += int(r["strict_ok"])
        heuristic_pass += int(r["heuristic_ok"])
        strict = f"slot{r['strict_slot']} {r['strict_reason'] or '—'}" if r["strict_ok"] else "—"
        heur = f"slot{r['heuristic_slot']} {r['heuristic_reason'] or '—'}" if r["heuristic_ok"] else "—"
        print(
            f"{r['capture']:<36} {r['winner']:<8} {strict:<18} {heur:<18} {r['ladder']}"
        )
        if r["win_hits"]:
            print(f"    win_hits={r['win_hits']}")
        if r["sur_hits"]:
            print(f"    sur_hits={r['sur_hits']}")

    print(f"\nStrict decode: {strict_pass}/{len(labels)} match labels")
    print(f"Ladder heuristic: {heuristic_pass}/{len(labels)} match labels")
    print("\nGhidra anchors (WA.exe): put_message=0x541130 surrender_team=0x55BB50")
    print("  process_surrender=0x5611E0 issue_next_win=0x55D270 msg_expand=0x564EA0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
