#!/usr/bin/env python3
"""Validate task-1020/1043 winner parsing against labeled captures."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from wormnetbot.wa_task_stream import (
    announced_result_from_bodies,
    count_400204_ladder_frames,
    parse_surrender_announcements,
    parse_win_announcements,
)

CAPTURES = Path("/opt/WormNETBot/captures")
LABELS = CAPTURES / "result_labels.json"


def load_capture(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def slot_for_name(rows: list[dict], name: str) -> int | None:
    for row in rows:
        if row.get("type") != "lobby_snapshot":
            continue
        for player in row.get("players", []):
            if player.get("nickname") == name and player.get("team_slot", 0) > 0:
                return player["team_slot"]
        for team in row.get("teams", []):
            if team.get("owner_nickname") == name and team.get("slot", 0) > 0:
                return team["slot"]
    return None


def endgame_bodies(rows: list[dict]) -> tuple[list[bytes], dict[str, list[bytes]]]:
    """All channel-2 inbound bodies and per-nickname lists."""
    all_bodies: list[bytes] = []
    by_nick: dict[str, list[bytes]] = {}
    for row in rows:
        if row.get("type") != "packet":
            continue
        if row.get("channel") != 2 or row.get("direction") != "in":
            continue
        body_hex = row.get("ws_payload_hex") or row.get("body_hex")
        if not body_hex:
            continue
        body = bytes.fromhex(body_hex)
        all_bodies.append(body)
        nick = row.get("nickname") or "?"
        by_nick.setdefault(nick, []).append(body)
    return all_bodies, by_nick


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Require task-1020/1043 only (no ladder heuristic)",
    )
    args = parser.parse_args()
    labels = json.loads(LABELS.read_text())
    ok = 0
    fail = 0
    for entry in labels:
        cap_path = CAPTURES / entry["capture"]
        rows = load_capture(cap_path)
        winner_name = entry["winner"]
        loser_name = entry["loser"]
        winner_slot = slot_for_name(rows, winner_name)
        loser_slot = slot_for_name(rows, loser_name)
        if winner_slot is None or loser_slot is None:
            print(f"FAIL {entry['capture']}: roster slots not found")
            fail += 1
            continue

        all_bodies, by_nick = endgame_bodies(rows)
        first_sentinel_slot = None
        for o in rows:
            if (
                o.get("channel") == 2
                and o.get("direction") == "in"
                and o.get("body_hex") == "400600"
            ):
                nick = o.get("nickname")
                slot = slot_for_name(rows, nick)
                if slot is not None:
                    first_sentinel_slot = slot
                    break
        ladder_counts: dict[int, int] = {}
        for nick, bodies in by_nick.items():
            slot = slot_for_name(rows, nick)
            if slot is None or slot == 0:
                continue
            n = sum(count_400204_ladder_frames(b) for b in bodies)
            if n:
                ladder_counts[slot] = n

        valid = {winner_slot, loser_slot}
        result = announced_result_from_bodies(all_bodies, valid)

        win_raw = []
        sur_raw = []
        for b in all_bodies:
            win_raw.extend(parse_win_announcements(b))
            sur_raw.extend(parse_surrender_announcements(b))

        if result and result.winner_slot == winner_slot:
            print(
                f"OK   {entry['capture']}: winner={winner_name} slot={winner_slot} "
                f"reason={result.reason} ladder={ladder_counts}"
            )
            ok += 1
        else:
            got = result.winner_slot if result else None
            print(
                f"FAIL {entry['capture']}: expected winner slot {winner_slot} ({winner_name}), "
                f"got {got} reason={result.reason if result else None} "
                f"ladder={ladder_counts} win_hits={win_raw[-3:]} sur_hits={sur_raw[-3:]}"
            )
            fail += 1

    print(f"\n{ok} passed, {fail} failed")
    return 0 if fail == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
