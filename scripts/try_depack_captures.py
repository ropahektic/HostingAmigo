#!/usr/bin/env python3
"""Run ``depack_wa_block`` on channel-2 bodies in a jsonl; print counts and sample OK sizes."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
if str(_REPO / "src") not in sys.path:
    sys.path.insert(0, str(_REPO / "src"))

from wormnetbot.wa_binary_depack import depack_wa_block  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("jsonl", type=Path, nargs="*", help="default: all captures/*.jsonl")
    ap.add_argument("--min-body", type=int, default=20, help="only bodies this long")
    args = ap.parse_args()
    paths = list(args.jsonl) if args.jsonl else sorted(Path("captures").glob("*.jsonl"))
    for path in paths:
        if not path.is_file():
            print("missing", path, file=sys.stderr)
            return 1
        ok = bad = 0
        for line in path.read_text().splitlines():
            o = json.loads(line)
            if o.get("type") != "packet" or o.get("channel") != 2:
                continue
            b = bytes.fromhex(o["body_hex"])
            if len(b) < args.min_body:
                continue
            r = depack_wa_block(b)
            if r:
                ok += 1
            else:
                bad += 1
        print(f"{path.name}  ch2>={args.min_body}:  ok {ok}  None/empty {bad}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
