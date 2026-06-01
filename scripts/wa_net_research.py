#!/usr/bin/env python3
"""
Live channel-2 (WormNET game) vs replay: **right layer to reverse**

## What went wrong

- **Replay (``.WAgame``)** uses a *serialized task stream* with first-byte tags and
  ``msg_expand`` (``*a1 = *a4 + 1000``). End-of-blob ``16 03`` is a **marker**, not
  “team X won” (see ``wa_serialization.py`` / ``replay_research.py``).
- **Rbot C2 ``body``** is **not** that same stream. Guessing “families” from
  ``body[:4].hex()`` (e.g. ``4021051e``) was **empirical**; it may tag *some* state,
  but it is not tied to **named** ``TaskMessageType`` values from the engine, so it
  can point at the last actor / wrong slot (e.g. suicide) while the true winner is
  another team.

## Better approach (use the symbolized build + IDA, then the bot’s captures)

Work **forwards** from code the binary already names:

1. **``surrender_team__13Task_TurnGamei``** and **``flush_surrendered_teams__13Task_TurnGame``**  
   Decompile; list every call to **``message__13Task_TurnGame``** (or
   **``message__9Task_Game``** / **``message__7Task_…``** in the same path) with a
   **numeric** second argument. That constant is the **C++ ``TaskMessageType``**
   (enum value), not the file’s first byte.
2. **``issue_next_win_message__13Task_TurnGameRi``** and **``game_is_over__13Task_TurnGame``**  
   Same: which **``TaskMessageType``** (if any) is sent when the match is decided?
3. For each type **T** you find in (1)–(2), convert to the **serialized first byte**
   used in **replay** if the same path uses ``msg_save``/``msg_compress``:
   ``v = T - 1000`` in the common band (see ``wa_serialization.py``). Use that to
   **search captures** (``body_hex``) for ``v`` at structurally valid offsets *only
   after* you know the **length layout** for that type from **``msg_save__7BE_Game``**
   or the **``msg_compress``** row for **T** (don’t guess length from C2 alone).
4. **Net send path** (names vary): find who copies the compressed buffer into the
   outgoing C2 frame (often after **``BE_Game``** or **``Net*``** / **``WormNet*``**).
   That answers “which bytes in ``body`` are the task blob vs frame wrapper.”
5. **Then** teach **Rbot** to decode *that* layout (or match a small set of
   **(type, body) → team index)** from the struct the decompiler shows), instead of
   ad-hoc family scoring.

## What the bot is for

- After you know one or more **(TaskMessageType, field that holds team/slot)** pairs,
  grep **``captures/*.jsonl``** for those patterns at game end and confirm against
  known results (1v1, 6-team, suicide finish).

## This script

- If ``game/WA/WA`` (or ``--binary`` / ``$WA``) exists: runs **``nm``** and prints
  addresses for symbols that match a short list (anchors for IDA).
- If the binary is missing: prints this help only.

**Ground truth on Windows (closest path to 100% winner correlation):** after you resolve
**``put_message__15TaskMessageFifo…``** in **your** ``WA.exe``/``WA Updated.exe`` IDA
database, set **``PUT_MESSAGE_RVA``** in ``scripts/frida_wa_ground_truth.js`` and run
Frida; compare logged **``(t, i, body head)``** to channel-2 captures at the same
game phase.

No IDA required to *run* this; use the printed addresses in your local IDA database
(jump to address, then **Xrefs** to find call sites).
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

# Default: **tight** name prefixes so we do not dump the whole vtable. Use --wide
# (below) to grep broadly for e.g. every ``*Task_TurnGame*`` symbol.
CORE_NAME_PREFIXES: tuple[str, ...] = (
    "put_message__15TaskMessageFifo",
    "surrender_team__13Task_TurnGamei",
    "flush_surrendered_teams__13Task_TurnGame",
    "issue_next_win_message__13Task_TurnGameRi",
    "game_is_over__13Task_TurnGame",
    "process_surrender__13Task_TurnGame",
    "check_for_survival_deaths__13Task_TurnGame",
    "check_for_vital_deaths__13Task_TurnGame",
    "message__13Task_TurnGameR4Task15TaskMessageTypeiP15TaskMessageBody",
    "message__9Task_GameR4Task15TaskMessageTypeiP15TaskMessageBody",
    "msg_save__7BE_GameP15TaskMessageFifo",
    "msg_load__7BE_GameP15TaskMessageFifo",
    "msg_compress__FPUc15TaskMessageTypeiP15TaskMessageBody",
    "get_message__15TaskMessageFifoiR15TaskMessageTypeRiP15TaskMessageBody",
    "msg_expand__FR15TaskMessageTypeRiP15TaskMessageBodyPUc",
    "comment_public__8GameTask",
)

# ``nm`` output line matches if the symbol *name* (first field) starts with one of these.
WIDE_NAME_PREFIXES: tuple[str, ...] = (
    "surrender_",
    "flush_surrendered_",
    "issue_next_win_",
    "game_is_over__",
    "message__13Task_TurnGameR",
    "message__9Task_GameR",
    "msg_save__7BE_",
    "msg_load__7BE_",
    "msg_compress__",
    "get_message__15Task",
    "msg_expand__",
    "comment_public__8GameTask",
    "check_for_",
    "process_surrender__",
    "lone_survival_",
    "process_turn_event__13",
    "emit_worm_kills_",
    "service__7BE_Game",
    "render__7BE_Game",
)

DEFAULT_BINARY = Path(__file__).resolve().parents[1] / "game" / "WA" / "WA"


def _find_nm() -> str | None:
    for name in ("nm", "llvm-nm"):
        from shutil import which

        p = which(name)
        if p:
            return p
    return None


def _nm_lines(binary: Path) -> list[str]:
    nm = _find_nm()
    if not nm:
        return []
    # -C: demangle (if supported); -P: portable; show all
    for args in (
        [nm, "-C", "-P", str(binary)],
        [nm, "-P", str(binary)],
    ):
        try:
            p = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=60,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        if p.returncode == 0 and p.stdout:
            return p.stdout.splitlines()
    return []


def _first_field(line: str) -> str:
    return line.split(None, 1)[0] if line.split() else ""


def _filter_symbols(lines: list[str], *, wide: bool) -> list[str]:
    prefs = WIDE_NAME_PREFIXES if wide else CORE_NAME_PREFIXES
    out: list[str] = []
    for line in lines:
        if not line.strip() or " U " in line:
            continue
        name = _first_field(line)
        if any(name.startswith(p) for p in prefs):
            out.append(line.strip())
    return sorted(set(out), key=_first_field)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="List WA symbol addresses for winner/task/net RE anchors (nm).",
    )
    parser.add_argument(
        "--binary",
        type=Path,
        default=Path(os.environ.get("WA", str(DEFAULT_BINARY))),
        help="Path to WA executable (default: $WA or game/WA/WA).",
    )
    parser.add_argument(
        "--wide",
        action="store_true",
        help="List more related symbols (noisier; for broad IDA browsing).",
    )
    args = parser.parse_args()
    b = args.binary
    if not b.is_file():
        print(__doc__)
        print(f"### Binary not found: {b}\n", file=sys.stderr)
        print("Set --binary or WA=/path/to/WA and re-run.\n", file=sys.stderr)
        return 1
    if not _find_nm():
        print("### `nm` not found; install binutils to list symbols.\n", file=sys.stderr)
        return 1
    lines = _nm_lines(b)
    if not lines:
        print(f"### nm produced no output for {b}\n", file=sys.stderr)
        return 1
    mode = "wide" if args.wide else "core (use --wide for more)"
    hits = _filter_symbols(lines, wide=bool(args.wide))
    print(f"== nm anchors for: {b} ({mode}) ==")
    if not hits:
        print("(no lines matched; try: nm -C {path} | less)")
        return 0
    for h in hits:
        print(h)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
