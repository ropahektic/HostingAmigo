#!/usr/bin/env python3
"""
Parse IDA ``exports/WA.lst`` (ELF ``WA``) and list ``Task::deliver`` call sites inside
named ``Task_TurnGame::*`` procedures — stack pushes are Intel syntax ``push NNNh``.

``deliver`` stdcall-ish order in this listing (args pushed right-to-left, last pushed first):

  TaskMessageBody * / size field
  int (often body size or flags)
  TaskMessageType (immediate ``NNNh``)
  int (team index / payload)
  TaskType (immediate ``NNh``)
  Task & (this, twice in samples)

We only scrape **hex immediates** on the lines immediately above ``call deliver__…`` within
each target function; verify in disassembly when wiring to Python.
"""
from __future__ import annotations

import argparse
import re
from pathlib import Path

DELIVER_RE = re.compile(r"call\s+deliver__4TaskR4Task8TaskTypei15TaskMessageTypeiP15TaskMessageBody")
CALL_ANY_RE = re.compile(r"^\s*call\s+", re.I)
# IDA: ``push 413h`` (hex) or ``push 4`` (decimal, no suffix)
PUSH_HEX_RE = re.compile(r"^\s*push\s+([0-9A-Fa-f]+)h\b", re.I)
PUSH_DEC_RE = re.compile(r"^\s*push\s+(\d+)\b")
PROC_START = re.compile(r"^\s*(\w+)\s+proc\s+near")
PROC_END = re.compile(r"^\s*(\w+)\s+endp")


def extract_functions(lst: str, names: frozenset[str]) -> dict[str, list[str]]:
    lines = lst.splitlines()
    active: str | None = None
    buf: dict[str, list[str]] = {n: [] for n in names}

    for raw in lines:
        line = raw.rstrip()
        m_end = PROC_END.match(line.strip())
        if m_end and m_end.group(1) == active:
            active = None
            continue
        m_start = PROC_START.match(line.strip())
        if m_start:
            sym = m_start.group(1)
            if sym in names:
                active = sym
            else:
                active = None
            continue
        if active:
            buf[active].append(line)
    return buf


def parse_push_imm_decimal_or_hex(line: str) -> int | None:
    s = line.strip()
    m = PUSH_HEX_RE.match(s)
    if m:
        return int(m.group(1), 16)
    m = PUSH_DEC_RE.match(s)
    if m:
        return int(m.group(1), 10)
    return None


def surrender_team_virtual_deliver_hint(body_lines: list[str]) -> list[str]:
    """``surrender_team`` uses vtable call, not a direct ``deliver`` label — same 0x413/0x124 as flush."""
    hits: list[str] = []
    for i, line in enumerate(body_lines):
        if "413h" not in line and "413H" not in line:
            continue
        lo = max(0, i - 6)
        hi = min(len(body_lines), i + 4)
        hits.append("---")
        hits.extend(body_lines[lo:hi])
    return hits


def deliver_sites(body_lines: list[str]) -> list[tuple[int, list[str]]]:
    """Return (line_index_in_body, context_lines) for each deliver call."""
    out: list[tuple[int, list[str]]] = []
    for i, line in enumerate(body_lines):
        if not DELIVER_RE.search(line):
            continue
        # Args are ``push``es immediately before ``call deliver``; stop at the *previous* ``call``
        # so we do not pull ``push``es from ``speech__`` / ``comment_public__`` / etc.
        pushes: list[str] = []
        j = i - 1
        steps = 0
        while j >= 0 and len(pushes) < 14 and steps < 120:
            steps += 1
            s = body_lines[j].strip()
            if CALL_ANY_RE.match(s):
                break
            if s.startswith("push"):
                pushes.insert(0, s)
            j -= 1
        out.append((i, pushes + [body_lines[i].strip()]))
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--lst",
        type=Path,
        default=Path(__file__).resolve().parent.parent / "exports" / "WA.lst",
        help="Path to WA.lst",
    )
    args = ap.parse_args()
    text = args.lst.read_text(encoding="utf-8", errors="replace")

    targets = frozenset(
        {
            "surrender_team__13Task_TurnGamei",
            "game_is_over__13Task_TurnGame",
            "issue_next_win_message__13Task_TurnGameRi",
            "flush_surrendered_teams__13Task_TurnGame",
        }
    )
    funcs = extract_functions(text, targets)

    for name in sorted(targets):
        body = funcs.get(name, [])
        sites = deliver_sites(body)
        print(f"\n=== {name} ===")
        if not sites:
            print("  (no direct call    deliver__4Task…    in this proc)")
        for _idx, (_li, block) in enumerate(sites):
            print(f"  site {_idx + 1}:")
            for ln in block:
                print(f"    {ln}")
            imms = [v for ln in block[:-1] if (v := parse_push_imm_decimal_or_hex(ln)) is not None]
            if imms:
                print(f"    numeric immediates (push order, bottom arg first on stack): {imms}")

        if name == "surrender_team__13Task_TurnGamei" and not sites:
            hint = surrender_team_virtual_deliver_hint(body)
            if hint:
                print("  vtable path (push 413h context):")
                for ln in hint:
                    print(f"    {ln}")


if __name__ == "__main__":
    main()
