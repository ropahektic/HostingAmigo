#!/usr/bin/env python3
"""Import OpenWA symbol names into Ghidra via LaurieWired GhidraMCP HTTP API.

Correct endpoint (POST): rename_function_by_address
  function_address=0x00536270&new_name=GameRuntime__BeginNetworkGameEnd

Do NOT use renameFunction (wrong params, always fails).
Preflight with get_function_by_address to skip addresses Ghidra has not analyzed as functions.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "third_party" / "OpenWA-re" / "wa_import.json"
DEFAULT_BASE = "http://192.168.1.59:8080"

FUN_RE = re.compile(r"^Function:\s+(\S+)\s+at\s+([0-9a-fA-F]+)", re.M)


def http_get(base: str, path: str, params: dict[str, str], timeout: float) -> str:
    qs = urllib.parse.urlencode(params)
    url = f"{base.rstrip('/')}/{path}?{qs}"
    with urllib.request.urlopen(url, timeout=timeout) as resp:
        return resp.read().decode(errors="replace").strip()


def http_post(base: str, path: str, params: dict[str, str], timeout: float) -> str:
    body = urllib.parse.urlencode(params).encode()
    req = urllib.request.Request(f"{base.rstrip('/')}/{path}", data=body, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode(errors="replace").strip()


def get_function(base: str, va: str, timeout: float) -> tuple[str | None, str]:
    try:
        msg = http_get(base, "get_function_by_address", {"address": va}, timeout)
    except Exception as exc:  # noqa: BLE001
        return None, str(exc)
    if "no function found" in msg.lower():
        return None, msg
    m = FUN_RE.search(msg)
    if m:
        return m.group(1), msg
    return None, msg


def rename(base: str, va: str, name: str, timeout: float) -> tuple[str, str]:
    """Return status: ok | skip | fail."""
    try:
        msg = http_post(
            base,
            "rename_function_by_address",
            {"function_address": va, "new_name": name},
            timeout,
        )
    except Exception as exc:  # noqa: BLE001
        return "fail", str(exc)
    low = msg.lower()
    if "successfully" in low:
        return "ok", msg
    if "no function" in low or "not find function" in low or "could not find function" in low:
        return "skip", msg
    return "fail", msg


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--base", default=DEFAULT_BASE)
    ap.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    ap.add_argument("--limit", type=int, default=0, help="Max symbols (0 = all)")
    ap.add_argument("--query", default="", help="Only names containing substring")
    ap.add_argument("--anchors-only", action="store_true", help="WormNETBot anchor VAs only")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--timeout", type=float, default=15.0)
    ap.add_argument("--progress", type=int, default=500)
    args = ap.parse_args()

    data = json.loads(args.manifest.read_text())
    symbols = [s for s in data.get("symbols", []) if s.get("kind") == "function" and s.get("name")]
    if args.query:
        q = args.query.lower()
        symbols = [s for s in symbols if q in s["name"].lower()]
    if args.anchors_only:
        anchors = {
            0x00534E00, 0x00536270, 0x00536470, 0x00541130, 0x00553BD0,
            0x0055BB50, 0x0055D270, 0x00561040, 0x005611E0, 0x005648B0,
            0x00564EA0, 0x0056DC10, 0x0056FAF0,
        }
        symbols = [s for s in symbols if int(s["va"], 16) in anchors]
    if args.limit:
        symbols = symbols[: args.limit]

    ok_n = skip_n = fail_n = already_n = nofun_n = 0
    t0 = time.time()
    for i, sym in enumerate(symbols, 1):
        va = sym["va"]
        if not va.startswith("0x"):
            va = f"0x{int(va):08X}"
        name = sym["name"]

        if args.dry_run:
            print(f"DRY {va} -> {name}")
            continue

        current, _ = get_function(args.base, va, args.timeout)
        if current is None:
            nofun_n += 1
            continue
        if current == name:
            already_n += 1
            continue

        status, msg = rename(args.base, va, name, args.timeout)
        if status == "ok":
            ok_n += 1
        elif status == "skip":
            skip_n += 1
        else:
            fail_n += 1
            if fail_n <= 15:
                print(f"FAIL {va} {current} -> {name}: {msg}", file=sys.stderr)

        if args.progress and i % args.progress == 0:
            elapsed = time.time() - t0
            print(
                f"... {i}/{len(symbols)} renamed={ok_n} already={already_n} "
                f"no_func={nofun_n} skip={skip_n} fail={fail_n} ({elapsed:.1f}s)"
            )

    elapsed = time.time() - t0
    print(
        f"Done: {len(symbols)} symbols in {elapsed:.1f}s — "
        f"renamed={ok_n}, already={already_n}, no_function={nofun_n}, skip={skip_n}, fail={fail_n}"
    )
    return 0 if fail_n == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
