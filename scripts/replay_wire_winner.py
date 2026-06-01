#!/usr/bin/env python3
"""Offline: would RBot infer winner from wire only (no sidecar)?"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from wormnetbot.wa_task_stream import (
    AnnouncedResult,
    announced_result_from_bodies,
    summarize_wire_re_gap,
)


@dataclass(frozen=True)
class TeamInfo:
    slot: int
    player_id: int
    owner_nickname: str
    team_name: str


def _game_started_snapshot(rows: list[dict]) -> dict | None:
    for row in rows:
        if row.get("type") == "lobby_snapshot" and row.get("label") == "game_started":
            return row
    for row in reversed(rows):
        if row.get("type") == "lobby_snapshot":
            return row
    return None


def human_roster(rows: list[dict]) -> dict[int, TeamInfo]:
    """One slot per player_id (same dedupe as RBot valid_slots)."""
    snap = _game_started_snapshot(rows)
    if snap is None:
        return {}
    by_player: dict[int, TeamInfo] = {}
    for team in sorted(snap.get("teams", []), key=lambda t: int(t.get("slot", 0))):
        slot = int(team.get("slot", 0))
        pid = int(team.get("player_id", 0))
        name = str(team.get("name", ""))
        nick = str(team.get("owner_nickname", "") or "")
        if slot <= 0 or pid <= 0 or name.endswith("'s team"):
            continue
        if pid not in by_player:
            by_player[pid] = TeamInfo(
                slot=slot,
                player_id=pid,
                owner_nickname=nick,
                team_name=name,
            )
    return {t.slot: t for t in by_player.values()}


def human_slots(rows: list[dict]) -> set[int]:
    return set(human_roster(rows).keys())


def describe_slot(slot: int | None, roster: dict[int, TeamInfo]) -> str:
    if slot is None:
        return "<none>"
    t = roster.get(slot)
    if t is None:
        return f"slot={slot} (?)"
    nick = t.owner_nickname or "?"
    team = t.team_name or "?"
    return f"{nick} ({team}) slot={slot}"


def load_labels(captures_dir: Path) -> dict[str, dict]:
    path = captures_dir / "result_labels.json"
    if not path.is_file():
        return {}
    try:
        raw = json.loads(path.read_text())
    except json.JSONDecodeError:
        return {}
    out: dict[str, dict] = {}
    for entry in raw:
        if isinstance(entry, dict) and entry.get("capture"):
            out[str(entry["capture"])] = entry
    return out


def _load_rows(cap: Path) -> list[dict]:
    rows: list[dict] = []
    with cap.open("rb") as f:
        for raw in f:
            line = raw.decode("utf-8", errors="replace").strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows


def collect_incoming_bodies(rows: list[dict], *, tail: int = 256) -> list[bytes]:
    bodies: list[bytes] = []
    for row in rows:
        if row.get("type") != "packet" or row.get("channel") != 2:
            continue
        if row.get("direction") != "in":
            continue
        body = bytes.fromhex(row.get("ws_payload_hex") or row.get("body_hex") or "")
        if body and body != b"\x40\x06\x00":
            bodies.append(body)
    if tail > 0:
        return bodies[-tail:]
    return bodies


def replay_capture(
    cap: Path, *, tail: int = 256
) -> tuple[AnnouncedResult | None, set[int], dict[int, TeamInfo], dict[str, object]]:
    rows = _load_rows(cap)
    roster = human_roster(rows)
    slots = set(roster.keys())
    bodies = collect_incoming_bodies(rows, tail=tail)
    result = announced_result_from_bodies(bodies, slots)
    gap = summarize_wire_re_gap(bodies)
    return result, slots, roster, gap


def _gap_tags(gap: dict[str, object]) -> str:
    parts: list[str] = []
    if gap.get("has_401e0202") and gap.get("has_0c14"):
        parts.append("401e02+14")
    elif gap.get("has_401e0202"):
        parts.append("401e02")
    if gap.get("has_401e0102"):
        parts.append("401e01")
    if gap.get("has_0c2b") or (gap.get("sur_hits_count", 0) or 0) > 0:
        parts.append("1043?")
    if gap.get("has_5c1f"):
        parts.append("5c1f")
    if gap.get("has_0c62"):
        parts.append("0c62")
    if not parts:
        parts.append("-")
    return ",".join(parts)


def _label_expected(label: dict | None) -> str | None:
    """How we expect strict wire decode to behave for labeled rank games."""
    if not label:
        return None
    if label.get("expect_wire") in ("1020", "1043", "miss", "any"):
        return str(label["expect_wire"])
    note = str(label.get("note") or "").lower()
    if label.get("winner_slot") is None:
        return None
    if "0c14" in note or "task-1020" in note or label.get("reason") == "task-1020":
        return "1020"
    if "1043" in note or "surrender" in note:
        return "1043"
    if "no 0c14" in note or "no 401e" in note or "0102" in note:
        return "miss"
    return "any"


def _validate_label(
    label: dict | None,
    result: AnnouncedResult | None,
    gap: dict[str, object],
) -> str:
    if not label or label.get("winner_slot") is None:
        return "-"
    exp_slot = int(label["winner_slot"])
    got_slot = result.winner_slot if result else None
    expect = _label_expected(label)

    if got_slot == exp_slot:
        return "OK"
    if got_slot is None and expect == "miss":
        return "OK(miss)"
    if got_slot is None:
        return "MISS"
    return "WRONG"


def print_result(
    cap: Path,
    result: AnnouncedResult | None,
    roster: dict[int, TeamInfo],
    gap: dict[str, object],
    *,
    label: dict | None = None,
    compact: bool = False,
    show_gap: bool = False,
) -> int:
    validate = _validate_label(label, result, gap)
    tags = _gap_tags(gap)

    if compact:
        if result is None or result.winner_slot is None:
            line = f"{cap.name}\tNO\t{tags}\t{validate}"
        else:
            w = describe_slot(result.winner_slot, roster)
            line = f"{cap.name}\t{result.reason}\t{w}\t{tags}\t{validate}"
        if label and label.get("winner_slot") is not None:
            line += f"\tL={label['winner_slot']}"
        if show_gap and validate not in ("OK", "-"):
            line += f"\t# {label.get('note', '')[:40] if label else ''}"
        print(line)
        return 0 if validate in ("OK", "OK(miss)", "-") else 1

    print(f"capture: {cap.name}")
    if roster:
        print("roster:")
        for slot in sorted(roster):
            print(f"  {describe_slot(slot, roster)}")
    else:
        print("roster: (none — missing game_started snapshot)")

    print(f"wire flags: {tags}")
    if gap.get("msg_save_frames"):
        for fr in gap["msg_save_frames"]:
            print(f"  msg_save {fr}")

    if result is None or result.winner_slot is None:
        print("wire-only: NO winner")
        if label:
            _print_label_hint(label, roster, validate)
        return 1 if validate not in ("OK(miss)", "-") else 0

    print(f"wire-only: WINNER  {describe_slot(result.winner_slot, roster)}")
    print(f"wire-only: LOSER   {describe_slot(result.loser_slot, roster)}")
    print(f"wire-only: reason={result.reason}")
    if label:
        _print_label_hint(label, roster, validate)
    return 0 if validate in ("OK", "-") else 1


def _print_label_hint(label: dict, roster: dict[int, TeamInfo], validate: str) -> None:
    exp_w = label.get("winner") or label.get("winner_nickname")
    exp_l = label.get("loser") or label.get("loser_nickname")
    ws = label.get("winner_slot")
    ls = label.get("loser_slot")
    parts: list[str] = []
    if validate not in ("OK", "-"):
        parts.append(f"validate={validate}")
    if exp_w or exp_l:
        parts.append(f"label says {exp_w or '?'} beat {exp_l or '?'}")
    if ws is not None:
        parts.append(f"expected winner {describe_slot(int(ws), roster)}")
    if ls is not None:
        parts.append(f"expected loser {describe_slot(int(ls), roster)}")
    note = label.get("note")
    if note:
        parts.append(str(note))
    if parts:
        print("expected: " + "; ".join(parts))


def looks_like_capture(cap: Path) -> bool:
    try:
        with cap.open("rb") as f:
            head = f.read(512)
    except OSError:
        return False
    if not head or not head.lstrip().startswith(b"{"):
        return False
    line = head.splitlines()[0].decode("utf-8", errors="replace")
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        return False
    return isinstance(obj, dict) and obj.get("type") in (
        "session_started",
        "packet",
        "lobby_snapshot",
    )


def default_capture(captures_dir: Path) -> Path:
    files = sorted(captures_dir.glob("*.jsonl"), key=lambda p: p.stat().st_mtime)
    if not files:
        raise SystemExit(f"no captures in {captures_dir}")
    return files[-1]


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "captures",
        nargs="*",
        type=Path,
        help="capture .jsonl file(s); default: newest in captures/",
    )
    p.add_argument(
        "--all",
        action="store_true",
        help="replay every *.jsonl in captures/ (newest last)",
    )
    p.add_argument(
        "--labels",
        action="store_true",
        help="show result_labels.json hints when present",
    )
    p.add_argument(
        "--compact",
        action="store_true",
        help="one tab-separated line per capture (implies terse output for --all)",
    )
    p.add_argument(
        "--validate",
        action="store_true",
        help="with --labels: check winner_slot vs strict decode (exit 1 on WRONG)",
    )
    p.add_argument(
        "--gap",
        action="store_true",
        help="show wire RE gap tags (401e02+14, 401e01, 5c1f, …)",
    )
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    base = Path(__file__).resolve().parents[1]
    captures_dir = base / "captures"
    use_labels = args.labels or args.all or args.validate
    labels = load_labels(captures_dir) if use_labels else {}

    if args.all:
        paths = sorted(
            (p for p in captures_dir.glob("*.jsonl") if looks_like_capture(p)),
            key=lambda p: p.stat().st_mtime,
        )
    elif args.captures:
        paths = [p if p.is_absolute() else (Path.cwd() / p) for p in args.captures]
    else:
        paths = [default_capture(captures_dir)]

    compact = args.compact or args.all
    show_gap = args.gap or args.validate or args.all
    failures = 0
    validate_failures = 0

    if compact and show_gap:
        print("capture\tdecode\twinner\twire-flags\tvs-label", file=sys.stderr)

    for cap in paths:
        if not cap.is_file():
            print(f"skip (missing): {cap}", file=sys.stderr)
            failures += 1
            continue
        if not looks_like_capture(cap):
            if not compact:
                print(f"skip (not jsonl capture): {cap.name}", file=sys.stderr)
            continue
        result, _slots, roster, gap = replay_capture(cap)
        label = labels.get(cap.name) if use_labels else None
        rc = print_result(
            cap,
            result,
            roster,
            gap,
            label=label,
            compact=compact,
            show_gap=show_gap,
        )
        if rc != 0:
            failures += 1
        if args.validate and label and label.get("winner_slot") is not None:
            v = _validate_label(label, result, gap)
            if v in ("WRONG", "MISS") and _label_expected(label) != "miss":
                validate_failures += 1
            elif v == "WRONG":
                validate_failures += 1
        if not compact and len(paths) > 1:
            print()

    if len(paths) > 1:
        ok = len(paths) - failures
        print(f"--- {ok}/{len(paths)} with wire winner ---", file=sys.stderr)
        if args.validate:
            print(
                f"--- labeled validation failures: {validate_failures} ---",
                file=sys.stderr,
            )
    if args.validate and validate_failures:
        return 1
    return 1 if failures and len(paths) == 1 else 0


if __name__ == "__main__":
    raise SystemExit(main())
