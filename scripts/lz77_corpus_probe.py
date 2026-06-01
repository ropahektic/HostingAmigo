#!/usr/bin/env python3
"""Probe rank captures for GameNet LZ77 decompress (offset scan on c070/4070)."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO / "src"))

from wormnetbot.wa_lz77 import lz77_decompress_try_offsets  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("jsonl", type=Path, nargs="?", help="capture jsonl (default: newest rank)")
    args = ap.parse_args()
    if args.jsonl:
        path = args.jsonl
    else:
        caps = sorted((_REPO / "captures").glob("*rank*.jsonl"), key=lambda p: p.stat().st_mtime)
        if not caps:
            print("no captures", file=sys.stderr)
            return 1
        path = caps[-1]
    print(f"capture: {path.name}")
    seen = 0
    for line in path.read_text().splitlines():
        o = json.loads(line)
        if o.get("type") != "packet" or o.get("channel") != 2:
            continue
        b = bytes.fromhex(o.get("body_hex") or "")
        if len(b) < 20 or b[1] != 0x70:
            continue
        seen += 1
        hits = lz77_decompress_try_offsets(b, max_decompressed=0x2000)
        print(
            f"  {o.get('direction')} {o.get('nickname')} len={len(b)} "
            f"head={b[:6].hex()} hits={len(hits)}"
        )
        for off, sp, dec in hits[:3]:
            print(f"    off={off} start_pos={sp} dec_len={len(dec)} head={dec[:20].hex()}")
    print(f"gamenet bodies scanned: {seen}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
