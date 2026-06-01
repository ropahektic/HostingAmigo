#!/usr/bin/env python3
"""
Offline research tool for `.WAgame` task/message streams (same parser as
`analyze_result_frames.py`). Use it to study *what the replay file encodes*,
separate from live channel-2 traffic.

## Findings (2026-04, n=5 “false positive” sessions, `Replays/*.WAgame`)

### `0x16` + second byte `0x03` — not a “winner index”

- Every parsed stream has **exactly one** `0x16` event, payload **two bytes**: `16 03`.
- The **raw file** ends with a long run of `0x02` padding and finally `16 03` (see
  `xxd` on a replay tail). So in practice this pair behaves like an **end-of-stream
  marker** for the serialized task/message blob, not a mid-simulation
  `TaskMessageType` you can read a team slot from.
- The name `game_end` in `REPLAY_EVENT_NAMES` is **our** label for opcode `0x16` in
  the *replay* format; it must not be confused with C++ `TaskMessageType` values in
  `TaskMessageFifo` / `message__9Task_Game` (those go through `msg_save` /
  `msg_compress` and a different encoding).

**Conclusion:** do not use `0x16`’s second byte as “winning team” without a new proof
from `msg_expand` / `get_message` / `msg_save` cross-reference in the WA binary.

### `0x70`–`0x73` (`var_player_info` in the parser) — bootstrap blob, not result

- In all five replays, there is **exactly one** `0x70`…`0x73` event in the **entire**
  file.
- It appears **immediately after** the first `0x09` (`frame0_checksum`) at the start
  of the task/message stream (event index 1). Payload is **high-entropy** (likely
  compressed or opaque per-player init), not a cleartext “slot X won”.

**Conclusion:** treat this as **session/seed/player snapshot at recording start**,
not a post-match result block.

### Where a “true winner” likely lives (for nizakawa / IDA follow-up)

1. **In-engine state:** `message__13Task_TurnGame`, `Task_Team`, `Game` — same places
   that drive `STAT_*WIN*` strings in `text strings` (UI), not a 2-byte replay tail.
2. **In the replay stream earlier:** elimination / round / match messages that the
   current fixed opcode table may map as `unknown_XX` — scan **opcode histograms** and
   compare replays with known outcomes.
3. **Mapping task:** trace `msg_save__7BE_Game` / `msg_compress__FPUc15TaskMessageType`
   in `game/WA/WA` to the bytes written into `.WAgame` so **replay opcode ↔
   `TaskMessageType`** is explicit (then search for types used on match/round end).

**Update (objdump on `game/WA/WA`):** see `wa_serialization.py` — the first **serialized**
byte in the replay uses `msg_expand`’s **index = byte - 2** (96 cases). So file byte
`0x16` is **case index 20**, *not* C++ `TaskMessageType == 0x16`. Engine types in
`msg_compress` use a separate range (`type - 0x3ea`).

This script automates histograms, `0x16` second-byte stats, `0x70` position reports,
and optional **unknown-opcode** counts (parser one-byte fallbacks).
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path

_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))

# Import the existing parser (single source of truth for stream layout).
import analyze_result_frames as ar
import wa_serialization as wa


def load_events(
    path: Path,
) -> tuple[int | None, list[dict[str, object]], Counter[int]]:
    data = path.read_bytes()
    off, events, unknowns = ar.locate_replay_stream(data)
    return off, events, unknowns


def report_0x16(path: Path, events: list[dict[str, object]]) -> str:
    lines: list[str] = [f"  0x16 events in {path.name}:"]
    for e in events:
        if int(e["opcode"]) != 0x16:
            continue
        b = bytes(e["data"])
        extra = f" off={e['offset']}" if e.get("offset") is not None else ""
        lines.append(f"    hex={b.hex()}{extra}  (byte1=0x{b[1]:02x} if len>=2)")
    if len(lines) == 1:
        lines.append("    <none>")
    return "\n".join(lines)


def report_var_player(path: Path, events: list[dict[str, object]]) -> str:
    lines: list[str] = [f"  0x70-0x73 in {path.name}:"]
    n = 0
    for i, e in enumerate(events):
        op = int(e["opcode"])
        if 0x70 <= op <= 0x73:
            n += 1
            b = bytes(e["data"])
            h = b.hex()
            if len(h) > 120:
                h = h[:120] + "..."
            lines.append(
                f"    #{i} op=0x{op:02x} len={len(b)} off={e.get('offset')} hex={h}"
            )
    if n == 0:
        lines.append("    <none>")
    return "\n".join(lines)


def first_events(path: Path, events: list[dict[str, object]], n: int) -> str:
    lines: list[str] = [f"  first {n} events in {path.name}:"]
    for i, e in enumerate(events[:n]):
        op = int(e["opcode"])
        name = ar.replay_event_name(op)
        team = ar.replay_event_team(e)
        ts = f" team={team}" if team is not None else ""
        lines.append(
            f"    {i:4} off={e.get('offset')} op=0x{op:02x} {name:22}{ts}"
        )
    return "\n".join(lines)


def opcode_histogram(events: list[dict[str, object]], top: int) -> str:
    c: Counter[int] = Counter()
    for e in events:
        c[int(e["opcode"])] += 1
    lines: list[str] = ["  opcode counts (top {}):".format(top)]
    for op, count in c.most_common(top):
        lines.append(
            f"    0x{op:02x} {ar.replay_event_name(op):24} {count}"
        )
    return "\n".join(lines)


def run(
    replays_dir: Path,
    list_first: int,
    hist_top: int,
    show_unknown: bool,
) -> str:
    paths = sorted(replays_dir.glob("*.WAgame"))
    if not paths:
        return f"no *.WAgame in {replays_dir}"

    global_16_byte1: Counter[int] = Counter()
    merged_unknown: Counter[int] = Counter()
    out: list[str] = [
        "== replay_research ==",
        "",
        "=== wa_serialization (see scripts/wa_serialization.py) ===",
        f"  first byte 0x16 -> TaskMessageType {wa.msg_expand_task_type_from_first_byte(0x16)} (0x{wa.msg_expand_task_type_from_first_byte(0x16):x})",
        f"  -> msg_compress index {wa.replay_first_byte_to_compress_index(0x16)} (type - 0x{wa.MSG_COMPRESS_TYPE_BASE:03x})",
        "",
    ]
    for path in paths:
        off, events, unknowns = load_events(path)
        if show_unknown:
            merged_unknown.update(unknowns)
        out.append(f"\n-- {path.name}")
        out.append(f"  stream_offset={off!r}  total_events={len(events)}")
        out.append(report_0x16(path, events))
        for e in events:
            if int(e["opcode"]) == 0x16 and len(e["data"]) >= 2:
                global_16_byte1[bytes(e["data"])[1]] += 1
        out.append(report_var_player(path, events))
        if list_first:
            out.append(first_events(path, events, list_first))
        out.append(opcode_histogram(events, hist_top))
        if show_unknown and unknowns:
            u_txt = ", ".join(f"0x{op:02x}×{n}" for op, n in unknowns.most_common(12)) or "<none>"
            out.append(f"  unknown opcodes (1-byte parse fallback): {u_txt}")

    out.append("\n== global: 0x16 second byte (all files) ==")
    for byte1, count in sorted(global_16_byte1.items()):
        out.append(f"  0x{byte1:02x}: {count}")
    if show_unknown and merged_unknown:
        out.append("\n== global: merged unknown opcodes ==")
        for op, n in merged_unknown.most_common(24):
            out.append(f"  0x{op:02x}  {n}")
    return "\n".join(out)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Research .WAgame task/message streams (0x16, 0x70-0x73, histograms).",
    )
    parser.add_argument(
        "--replays-dir",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "Replays",
        help="Directory containing .WAgame files (default: project Replays/)",
    )
    parser.add_argument(
        "--list-first",
        type=int,
        default=8,
        help="Print first N events per file (0 to disable).",
    )
    parser.add_argument(
        "--hist-top",
        type=int,
        default=18,
        help="How many opcodes to show in the frequency table.",
    )
    parser.add_argument(
        "--unknown",
        action="store_true",
        help="Include unknown opcode counts (per file + merged) from the parser.",
    )
    args = parser.parse_args()
    text = run(args.replays_dir, args.list_first, args.hist_top, args.unknown)
    print(text)


if __name__ == "__main__":
    main()
