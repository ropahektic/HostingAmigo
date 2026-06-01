#!/usr/bin/env python3
"""Shrink ida_largest_functions.txt: sort by size (column 1) descending, keep top N.

Example:
  python3 scripts/ida_largest_top.py exports/ida_largest_functions.txt -n 200 \\
    -o exports/ida_largest_top200.txt
"""
from __future__ import annotations

import argparse
from pathlib import Path


def main() -> int:
    p = argparse.ArgumentParser(
        description="Top-N largest functions from ida_largest_functions.txt (TSV).",
    )
    p.add_argument(
        "input",
        type=Path,
        help="Path to ida_largest_functions.txt",
    )
    p.add_argument(
        "-n",
        type=int,
        default=400,
        help="How many lines to keep (default 400).",
    )
    p.add_argument(
        "-o",
        "--out",
        type=Path,
        help="Output path (default: <input_stem>_top{n}.txt next to input).",
    )
    args = p.parse_args()
    text = args.input.read_text(encoding="utf-8", errors="replace")
    # ida .idc can emit many duplicate lines for the same (start) — one row per function start
    by_start: dict[str, tuple[int, str]] = {}
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        parts = line.split("\t", 3)
        if len(parts) < 4:
            continue
        try:
            size = int(parts[0], 16)
        except ValueError:
            continue
        start = parts[1]
        old = by_start.get(start)
        if old is None or size > old[0]:
            by_start[start] = (size, line)
    rows: list[tuple[int, str]] = list(by_start.values())
    rows.sort(key=lambda t: -t[0])
    top = [t[1] for t in rows[: max(0, args.n)]]
    out: Path
    if args.out:
        out = args.out
    else:
        out = args.input.parent / f"{args.input.stem}_top{args.n}.txt"
    out.write_text(
        f"# top {len(top)} by size (from {args.input.name}), unsorted in IDC\n"
        + "\n".join(top)
        + "\n",
        encoding="utf-8",
    )
    print(f"Wrote {len(top)} lines -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
