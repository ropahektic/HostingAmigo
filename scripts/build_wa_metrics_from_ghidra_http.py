#!/usr/bin/env python3
"""Build wa_metrics.json from live Ghidra HTTP (MCP bridge).

Uses:
  - searchFunctions / get_function_by_address for symbols
  - decompile_function to enumerate direct callees (call names)
  - xrefs_to for incoming call edges

When GUI export is unavailable, this is enough for ghidra_metrics_callers.py.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

GHIDRA_DEFAULT = "http://192.168.1.59:8080"

SEED_QUERIES = [
    "issue_next_win_message",
    "flush_surrendered",
    "game_is_over",
    "SurrenderTeam",
    "BaseEntity__deliver",
    "msg_expand",
    "msg_compress",
    "GameNet__send_block",
    "GameNet__update_incoming",
    "GameNet__update_application",
    "BeginNetworkGameEnd",
    "update_network_game",
    "put_message",
    "Task_TurnGame",
    "msg_save",
    "TurnManager__ProcessFrame",
    "WorldRootEntity__HandleMessage",
    "Game__setup_netclose",
    "Worms2Application__flush_network",
    "WS_GameNet__update",
    "check_for_vital_deaths",
    "check_for_survival_deaths",
]

CALL_RE = re.compile(r"\b([A-Za-z][A-Za-z0-9_]*__\w+)\s*\(")
XREF_FROM_RE = re.compile(
    r"From\s+([0-9a-fA-F]+)\s+in\s+(\S+)",
)
FUNC_LINE_RE = re.compile(r"^(.+?)\s+@\s+([0-9a-fA-F]+)\s*$", re.MULTILINE)
FUNC_HDR_RE = re.compile(r"^Function:\s+(.+?)\s+at\s+([0-9a-fA-F]+)")


class GhidraHttp:
    def __init__(self, base: str, delay: float = 0.02) -> None:
        self.base = base.rstrip("/")
        self.delay = delay
        self._name_cache: dict[str, int] = {}

    def get(self, path: str, timeout: float = 60.0) -> str:
        time.sleep(self.delay)
        req = urllib.request.Request(f"{self.base}/{path.lstrip('/')}")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")

    def search_va(self, query: str) -> list[tuple[str, int]]:
        text = self.get(f"searchFunctions?query={urllib.parse.quote(query)}")
        out: list[tuple[str, int]] = []
        for m in FUNC_LINE_RE.finditer(text):
            out.append((m.group(1), int(m.group(2), 16)))
        return out

    def resolve_name(self, name: str) -> int | None:
        if name in self._name_cache:
            return self._name_cache[name]
        # Strip __ suffix variants
        hits = self.search_va(name.split("(")[0])
        if not hits:
            short = name.replace("WorldRootEntity__", "").replace("GameNet__", "")
            hits = self.search_va(short)
        if hits:
            self._name_cache[name] = hits[0][1]
            return hits[0][1]
        return None

    def function_info(self, va: int) -> tuple[str, int]:
        text = self.get(f"get_function_by_address?address=0x{va:x}")
        name = f"FUN_{va:x}"
        size = 0
        for line in text.splitlines():
            m = FUNC_HDR_RE.match(line.strip())
            if m:
                name = m.group(1)
            if line.strip().lower().startswith("body:"):
                parts = line.split("-")
                if len(parts) >= 2:
                    try:
                        end = int(parts[-1].strip(), 16)
                        size = max(0, end - va)
                    except ValueError:
                        pass
        return name, size

    def callees_from_decompile(self, va: int) -> list[int]:
        try:
            text = self.get(f"decompile_function?address=0x{va:x}", timeout=120.0)
        except urllib.error.URLError as e:
            print(f"decompile {va:#x}: {e}", file=sys.stderr)
            return []
        names = sorted(set(CALL_RE.findall(text)))
        callees: list[int] = []
        for n in names:
            tva = self.resolve_name(n)
            if tva is not None and tva != va:
                callees.append(tva)
        return sorted(set(callees))

    def callers_from_xrefs(self, va: int) -> list[int]:
        text = self.get(f"xrefs_to?address=0x{va:x}")
        callers: set[int] = set()
        for line in text.splitlines():
            m = XREF_FROM_RE.search(line)
            if not m:
                continue
            site = int(m.group(1), 16)
            # Map call site -> containing function via search on symbol in line
            sym = m.group(2)
            hits = self.search_va(sym)
            if hits:
                callers.add(hits[0][1])
            else:
                # Resolve call site to function entry
                try:
                    ftext = self.get(f"get_function_by_address?address=0x{site:x}")
                    mh = FUNC_HDR_RE.search(ftext)
                    if mh:
                        callers.add(int(mh.group(2), 16))
                except urllib.error.URLError:
                    pass
        return sorted(callers)


def expand_graph(g: GhidraHttp, seeds: set[int], depth: int) -> set[int]:
    seen = set(seeds)
    frontier = list(seeds)
    for _ in range(depth):
        nxt: list[int] = []
        for va in frontier:
            for c in g.callees_from_decompile(va):
                if c not in seen:
                    seen.add(c)
                    nxt.append(c)
            for c in g.callers_from_xrefs(va):
                if c not in seen:
                    seen.add(c)
                    nxt.append(c)
        frontier = nxt
        print(f"  depth expand -> {len(seen)} functions", file=sys.stderr)
    return seen


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("url", nargs="?", default=GHIDRA_DEFAULT)
    ap.add_argument("-o", "--output", default="/tmp/wa_metrics.json")
    ap.add_argument("--depth", type=int, default=2)
    args = ap.parse_args()

    g = GhidraHttp(args.url)
    seeds: set[int] = set()
    print("Resolving seeds...", file=sys.stderr)
    for q in SEED_QUERIES:
        for name, va in g.search_va(q):
            seeds.add(va)
    print(f"  {len(seeds)} seed VAs", file=sys.stderr)

    vas = sorted(expand_graph(g, seeds, args.depth))
    functions: list[dict] = []
    for i, va in enumerate(vas):
        name, size = g.function_info(va)
        callees = g.callees_from_decompile(va)
        functions.append(
            {
                "name": name,
                "va": va,
                "size": size,
                "instruction_count": 0,
                "cyclomatic_complexity": 1,
                "callees": callees,
                "indirect_callees": [],
            }
        )
        if (i + 1) % 10 == 0:
            print(f"  built {i + 1}/{len(vas)}", file=sys.stderr)

    out_obj = {"functions": functions, "entry_points": [], "vtable_data": []}
    Path(args.output).write_text(json.dumps(out_obj, indent=2), encoding="utf-8")
    print(f"Wrote {args.output} ({len(functions)} functions)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
