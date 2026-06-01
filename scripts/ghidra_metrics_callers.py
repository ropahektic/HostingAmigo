#!/usr/bin/env python3
"""Find who calls endgame-related functions using OpenWAExportMetrics output.

Run on wormstv after Ghidra: Tools → OpenWA → Export metrics
(default writes C:/tmp/wa_metrics.json).

Usage:
  python3 ghidra_metrics_callers.py C:/tmp/wa_metrics.json
  python3 ghidra_metrics_callers.py C:/tmp/wa_metrics.json --targets issue_next,send_block
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

# Ghidra image-base VAs (WA.exe @ 0x400000)
TARGETS: dict[str, int] = {
    "issue_next_win": 0x0055D270,
    "flush_surrendered": 0x00561040,
    "game_is_over": 0x0055CC40,
    "SurrenderTeam": 0x0055BB50,
    "deliver": 0x00562EF0,
    "msg_expand": 0x00564EA0,
    "msg_compress": 0x005648B0,
    "send_block": 0x0053E380,
    "update_incoming_1": 0x0053E020,
    "update_application": 0x0053E170,
    "BeginNetworkGameEnd": 0x00536270,
    "update_network_game": 0x0052DCC0,
}


def load_metrics(path: Path) -> tuple[dict[int, dict], dict[int, list[int]]]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    by_va: dict[int, dict] = {}
    callers: dict[int, list[int]] = {va: [] for va in TARGETS.values()}
    for fn in raw.get("functions", []):
        va = int(fn["va"])
        by_va[va] = fn
        for callee in fn.get("callees", []):
            c = int(callee)
            if c in callers:
                callers[c].append(va)
    return by_va, callers


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("metrics", type=Path, help="wa_metrics.json from OpenWAExportMetrics")
    ap.add_argument(
        "--targets",
        nargs="*",
        default=list(TARGETS.keys()),
        help=f"subset of {', '.join(TARGETS)}",
    )
    args = ap.parse_args()
    if not args.metrics.is_file():
        print(f"missing: {args.metrics}")
        print("In Ghidra: Tools → OpenWA → Export metrics")
        return 1

    by_va, callers = load_metrics(args.metrics)
    print(f"loaded {len(by_va)} functions from {args.metrics}\n")

    for name in args.targets:
        va = TARGETS.get(name)
        if va is None:
            print(f"unknown target: {name}")
            continue
        fn = by_va.get(va)
        title = fn["name"] if fn and fn.get("name") else f"FUN_{va:x}"
        print(f"=== {name} @ {va:#x} ({title}) ===")
        who = sorted(callers.get(va, []))
        if not who:
            print("  (no direct callers in metrics — try Ghidra References → to)")
        for caller_va in who:
            cfn = by_va.get(caller_va, {})
            cname = cfn.get("name") or f"FUN_{caller_va:x}"
            nc = len(cfn.get("callees", []))
            print(f"  called from {caller_va:#x}  {cname}  ({nc} callees)")
        if fn:
            callees = [int(x) for x in fn.get("callees", [])]
            print(f"  calls -> {len(callees)} direct:")
            for c in callees[:12]:
                cn = by_va.get(c, {}).get("name") or f"FUN_{c:x}"
                mark = " ***" if c in TARGETS.values() else ""
                print(f"    {c:#x}  {cn}{mark}")
            if len(callees) > 12:
                print(f"    ... +{len(callees) - 12} more")
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
