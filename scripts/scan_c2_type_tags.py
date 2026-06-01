#!/usr/bin/env python3
"""
Scan a channel-2 capture (jsonl) for byte patterns that *might* match
TaskMessageType values from RE (e.g. win 1020, surrender 1043) **if** the
serialized stream used the +1000 / first-tag rule (v = type - 1000):

  1020 -> v = 20 = 0x14
  1043 -> v = 43 = 0x2B

This does **not** prove those bytes are “the winner” — it answers: “do these
values appear in ``body`` at all near game end, and where?”  If you never get
hits, the net path is probably wrapped (prefix, multiple records, or different
encoding) and the next step is **``put_message``/``msg_save`` → send** in IDA
or a hex dump of one frame in Wireshark.

Usage:
  python3 scan_c2_type_tags.py captures/foo.jsonl
  python3 scan_c2_type_tags.py captures/foo.jsonl --last-packets 80
"""

from __future__ import annotations

import argparse
import json
import struct
import sys
from pathlib import Path


def _body_hexes(
    path: Path,
    *,
    last_n: int | None,
) -> list[tuple[int, int, str, bytes]]:
    """(seq, frame, direction, body) for channel-2 packets, in file order."""
    out: list[tuple[int, int, str, bytes]] = []
    for line in path.read_text().splitlines():
        o = json.loads(line)
        if o.get("type") != "packet" or o.get("channel") != 2:
            continue
        hx = o.get("ws_payload_hex") or o["body_hex"]
        b = bytes.fromhex(hx)
        out.append(
            (
                int(o["seq"]),
                int(o.get("frame", 0)),
                str(o.get("direction", "")),
                b,
            )
        )
    if last_n is not None and len(out) > last_n:
        out = out[-last_n:]
    return out


def _scan(
    data: bytes,
    needles: list[tuple[str, int]],
) -> list[tuple[int, str, int]]:
    """List (offset, label, value) for each match."""
    hits: list[tuple[int, str, int]] = []
    for name, v in needles:
        needle = bytes([v])
        i = 0
        while True:
            j = data.find(needle, i)
            if j < 0:
                break
            hits.append((j, name, v))
            i = j + 1
    return sorted(hits, key=lambda t: t[0])


def main() -> int:
    ap = argparse.ArgumentParser(description="Hunt 0x14/0x2B (or custom) in C2 bodies")
    ap.add_argument(
        "jsonl",
        type=Path,
        nargs="?",
        default=None,
        help="Capture file (jsonl). If omitted, uses the first ``captures/*.jsonl`` under the repo root.",
    )
    ap.add_argument(
        "--last-packets",
        type=int,
        default=120,
        help="Only scan the last N ch2 rows (infile order). Default: 120",
    )
    ap.add_argument(
        "--types",
        default="1020,1043",
        help="TaskMessageType decimals to try as v=type-1000 single byte (default: 1020,1043)",
    )
    ap.add_argument(
        "--dword-le",
        action="store_true",
        help="Also look for full TaskMessageType as little-endian uint32 in body (stronger, fewer false hits)",
    )
    args = ap.parse_args()
    jsonl = args.jsonl
    if jsonl is None:
        root = Path(__file__).resolve().parents[1]
        found = sorted((root / "captures").glob("*.jsonl"))
        if not found:
            print(
                "No jsonl path given and no captures/*.jsonl under the repo.\n"
                "  python3 scripts/scan_c2_type_tags.py /path/to/channel2.jsonl",
                file=sys.stderr,
            )
            return 1
        jsonl = found[0]
        print(f"(using default capture: {jsonl})", file=sys.stderr)
    types = [int(x.strip(), 0) for x in args.types.split(",") if x.strip()]
    needles: list[tuple[str, int]] = []
    dwords: list[bytes] = []
    for t in types:
        v = t - 1000
        if 0 <= v <= 255:
            needles.append((f"byte_v=type-1000 type_{t} 0x{v:02x}", v))
        if args.dword_le and 0 <= t < 0x1000000:
            dwords.append((f"le_u32_TaskMessageType_{t}", struct.pack("<I", t)))
    rows = _body_hexes(jsonl, last_n=args.last_packets)
    nsum = f"bytes:{[n[0] for n in needles]}"
    if dwords:
        nsum += f" + le_u32:{[d[0] for d in dwords]}"
    print("==", jsonl, "ch2 rows:", len(rows), nsum, "==\n")
    for seq, frame, direction, body in rows:
        if direction != "in":
            continue
        h = _scan(body, needles)
        dw_hits: list[str] = []
        for dname, pat in dwords:
            i = 0
            while True:
                j = body.find(pat, i)
                if j < 0:
                    break
                dw_hits.append(f"({j},{dname})")
                i = j + 1
        if not h and not dw_hits:
            continue
        short = body[:64].hex() if len(body) > 64 else body.hex()
        print(
            f"seq={seq} frame=0x{frame:08x} in len={len(body)} byte_hits={h!s} u32_hits={dw_hits!s}"
        )
        print(f"  head: {short}{'...' if len(body) > 64 else ''}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
