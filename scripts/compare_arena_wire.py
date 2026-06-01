#!/usr/bin/env python3
"""Compare OpenWA arena ground truth (sidecar) vs strict C2 task decode per capture.

The sidecar is RE infrastructure: it labels what WA.exe team_arena says at game-over.
Wire decode must converge to the same winner/loser without OpenWA in the match.

Usage (CT104):
  PYTHONPATH=/opt/WormNETBot/src python3 scripts/compare_arena_wire.py
  PYTHONPATH=/opt/WormNETBot/src python3 scripts/compare_arena_wire.py captures/20260528T163658Z-rank.jsonl
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from wormnetbot.wa_gamenet_containers import extract_msg_save_stream
from wormnetbot.wa_task_stream import (
    announced_result_from_bodies,
    parse_surrender_announcements,
    parse_win_announcements,
)

CAPTURES = Path("/opt/WormNETBot/captures")
LABELS = CAPTURES / "result_labels.json"


def load_rows(path: Path) -> list[dict]:
    rows: list[dict] = []
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows


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


def human_slots(rows: list[dict]) -> set[int]:
    slots: set[int] = set()
    for row in rows:
        if row.get("type") != "lobby_snapshot":
            continue
        for team in row.get("teams", []):
            slot = team.get("slot", 0)
            if slot > 0 and not str(team.get("name", "")).endswith("'s team"):
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


def arena_truth(rows: list[dict]) -> dict[str, object] | None:
    """Ground truth from capture winner_inferred (openwa-arena) or result_labels."""
    for row in reversed(rows):
        if row.get("type") == "winner_inferred" and row.get("reason") == "openwa-arena":
            return {
                "source": "capture-sidecar",
                "winner_slot": row.get("winner_slot"),
                "loser_slot": row.get("loser_slot"),
                "survivors": row.get("survivor_team_idx_1based"),
                "hud": row.get("hud_status_code"),
                "ts": row.get("ts"),
            }
    return None


def wire_scan_summary(bodies: list[bytes]) -> dict[str, object]:
    win_all: list[tuple[int, int]] = []
    sur_all: list[tuple[int, int]] = []
    n_5c1f = 0
    n_401e = 0
    n_5c1f_inner = 0
    for body in bodies:
        if body.startswith(b"\x5c\x1f\x02\x02"):
            n_5c1f += 1
            inner = extract_msg_save_stream(body)
            if inner:
                n_5c1f_inner += len(inner)
        if body.startswith(b"\x40\x1e\x02\x02"):
            n_401e += 1
        win_all.extend(parse_win_announcements(body))
        sur_all.extend(parse_surrender_announcements(body))
    return {
        "win_hits": win_all[-8:],
        "sur_hits": sur_all[-8:],
        "containers_5c1f": n_5c1f,
        "containers_401e": n_401e,
        "5c1f_inner_chunks": n_5c1f_inner,
    }


def compare_capture(path: Path, labels_entry: dict | None) -> dict[str, object]:
    rows = load_rows(path)
    slots = human_slots(rows)
    if len(slots) < 2 and labels_entry:
        w = slot_for_name(rows, labels_entry["winner"])
        l = slot_for_name(rows, labels_entry["loser"])
        if w and l:
            slots = {w, l}
    bodies = endgame_bodies(rows)
    arena = arena_truth(rows)
    if arena is None and labels_entry:
        w = slot_for_name(rows, labels_entry["winner"])
        l = slot_for_name(rows, labels_entry["loser"])
        if w:
            arena = {
                "source": "result_labels.json",
                "winner_slot": w,
                "loser_slot": l,
                "survivors": None,
                "hud": None,
            }
    wire = announced_result_from_bodies(bodies, slots) if slots else None
    scan = wire_scan_summary(bodies)
    arena_w = arena.get("winner_slot") if arena else None
    wire_w = wire.winner_slot if wire else None
    match = arena_w is not None and wire_w is not None and arena_w == wire_w
    return {
        "capture": path.name,
        "human_slots": sorted(slots),
        "arena": arena,
        "wire": None
        if wire is None
        else {
            "winner_slot": wire.winner_slot,
            "loser_slot": wire.loser_slot,
            "reason": wire.reason,
        },
        "wire_scan": scan,
        "agree": match,
        "gap": "wire-missing"
        if arena_w is not None and wire_w is None
        else ("arena-missing" if arena_w is None and wire_w is not None else ("mismatch" if arena_w != wire_w else "ok")),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("captures", nargs="*", help="Capture jsonl paths (default: all in captures/)")
    parser.add_argument("--json", action="store_true", help="Emit JSON lines")
    args = parser.parse_args()

    label_by_capture: dict[str, dict] = {}
    if LABELS.is_file():
        for entry in json.loads(LABELS.read_text()):
            label_by_capture[entry["capture"]] = entry

    if args.captures:
        paths = [Path(p) for p in args.captures]
    else:
        paths = sorted(CAPTURES.glob("*.jsonl"), key=lambda p: p.stat().st_mtime, reverse=True)

    reports: list[dict[str, object]] = []
    for p in paths:
        try:
            reports.append(compare_capture(p, label_by_capture.get(p.name)))
        except OSError as exc:
            print(f"SKIP {p.name}: {exc}", file=sys.stderr)
    if args.json:
        for r in reports:
            print(json.dumps(r))
        return 0

    agree = sum(1 for r in reports if r["gap"] == "ok")
    wire_ok = sum(1 for r in reports if r["wire"] and r["wire"].get("winner_slot"))
    arena_ok = sum(1 for r in reports if r["arena"] and r["arena"].get("winner_slot"))
    print(f"Compared {len(reports)} captures: arena={arena_ok} wire={wire_ok} agree={agree}\n")
    for r in reports:
        arena = r["arena"] or {}
        wire = r["wire"] or {}
        print(
            f"{r['capture']}: gap={r['gap']} "
            f"arena={arena.get('winner_slot')} ({arena.get('source')}) "
            f"wire={wire.get('winner_slot')} ({wire.get('reason')}) "
            f"win_hits={len(r['wire_scan']['win_hits'])} sur_hits={len(r['wire_scan']['sur_hits'])} "
            f"5c1f={r['wire_scan']['containers_5c1f']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
