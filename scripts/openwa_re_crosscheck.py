#!/usr/bin/env python3
"""Cross-check WormNETBot Ghidra anchors against OpenWA re/ catalog."""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

try:
    import tomllib
except ImportError:
    import tomli as tomllib  # type: ignore

ROOT = Path(__file__).resolve().parents[1]
RE_DIR = ROOT / "third_party" / "OpenWA-re"
WA_TXT = ROOT / "WA.txt"
MANIFEST = RE_DIR / "wa_import.json"

# WormNETBot endgame / network anchors (WA.exe VAs)
ANCHORS = {
    0x00541130: "TaskMessageFifo.put_message / EntityMessage path",
    0x00536270: "GameRuntime.BeginNetworkGameEnd",
    0x00536470: "GameRuntime.OnNetworkEndAwaitPeers",
    0x00534E00: "GameRuntime.RenderNetworkEndWaitTextbox",
    0x00553BD0: "Task_Game.message (C2 relay)",
    0x0055BB50: "WorldRootEntity.surrender_team (OpenWA)",
    0x0055D270: "TurnGame.issue_next_win_message",
    0x00561040: "WorldRootEntity.flush_surrendered_teams (OpenWA)",
    0x005611E0: "TurnGame.process_surrender",
    0x005648B0: "EntityMessage.msg_compress",
    0x00564EA0: "EntityMessage.msg_expand",
    0x0056DC10: "Worms2Application.flush_network",
    0x0056FAF0: "DD_Game.msg_save (GameRuntime vtable)",
}


def parse_wa_txt() -> dict[int, str]:
    out: dict[int, str] = {}
    if not WA_TXT.is_file():
        return out
    for line in WA_TXT.read_text(errors="replace").splitlines():
        m = re.match(r"\s*(.+?)\s+(0x[0-9A-Fa-f]+)\s*$", line.strip())
        if not m:
            continue
        out[int(m.group(2), 16)] = m.group(1).strip()
    return out


def load_openwa_functions() -> dict[int, str]:
    out: dict[int, str] = {}
    for path in sorted(RE_DIR.glob("**/*.toml")):
        try:
            data = tomllib.loads(path.read_text(errors="replace"))
        except Exception:
            continue
        for fn in data.get("function", []):
            va = fn.get("va")
            name = fn.get("name")
            if va is None or not name:
                continue
            if isinstance(va, str):
                va = int(va, 16) if va.startswith("0x") else int(va)
            out[int(va)] = str(name)
    return out


def entity_message_enum() -> list[tuple[str, int]]:
    path = RE_DIR / "entity" / "EntityMessage.toml"
    if not path.is_file():
        return []
    data = tomllib.loads(path.read_text())
    for block in data.get("enum", []):
        if block.get("name") != "EntityMessage":
            continue
        variants = block.get("variant") or {}
        return sorted(((k, int(v)) for k, v in variants.items()), key=lambda x: x[1])
    return []


def main() -> int:
    wa = parse_wa_txt()
    ow = load_openwa_functions()
    print("OpenWA re/ functions:", len(ow))
    print("WA.txt symbols:", len(wa))
    print()
    print("Anchor cross-check (WormNETBot -> OpenWA):")
    for va, note in sorted(ANCHORS.items()):
        ow_name = ow.get(va, "—")
        wa_name = wa.get(va, "—")
        ok = ow_name != "—"
        mark = "OK" if ok else "MISS"
        print(f"  [{mark}] 0x{va:08X}  {note}")
        print(f"         OpenWA: {ow_name}")
        if wa_name != "—":
            print(f"         WA.txt: {wa_name}")
    print()
    interesting = ("Surrender", "TeamVictory", "TurnEnd", "MachineQuit", "msg_compress", "msg_expand", "BeginNetwork", "NetworkEnd")
    print("OpenWA names matching endgame/network:")
    for va, name in sorted(ow.items()):
        if any(k.lower() in name.lower() for k in interesting):
            print(f"  0x{va:08X}  {name}")
    print()
    em = entity_message_enum()
    if em:
        print("EntityMessage (OpenWA canonical):")
        for k, v in em:
            if k in ("Surrender", "TeamVictory", "TurnEndMaybe", "MachineQuit", "GameOver"):
                print(f"  {k} = 0x{v:02X}  (wire+1000 -> {v+1000} if msg_expand band)")
    if MANIFEST.is_file():
        m = json.loads(MANIFEST.read_text())
        print()
        print(f"wa_import.json: {len(m.get('symbols',[]))} symbols, {len(m.get('functions',[]))} function entries")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
