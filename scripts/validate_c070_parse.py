#!/usr/bin/env python3
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from wormnetbot.wa_gamenet_wire import parse_c070_envelope

fail = 0
masks = blobs = 0
root = Path(sys.argv[1] if len(sys.argv) > 1 else "captures")
for p in root.glob("*rank*.jsonl"):
    for line in open(p):
        o = json.loads(line)
        if o.get("type") != "packet" or o.get("channel") != 2:
            continue
        b = bytes.fromhex(o.get("body_hex") or "")
        if len(b) < 2 or b[1] != 0x70:
            continue
        env = parse_c070_envelope(b)
        if env is None:
            fail += 1
            print("fail", p.name, len(b), b[:16].hex())
        elif env.is_host_mask:
            masks += 1
        elif env.is_game_blob:
            blobs += 1
print("masks", masks, "blobs", blobs, "fail", fail)
