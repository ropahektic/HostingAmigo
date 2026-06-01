#!/usr/bin/env python3
"""
Find a hex byte string in a PE32 exe and print file offset + common VA (image base 0x400000).
Usage:
  python3 pe_bfind.py "../WA Updated.exe" "8b,45,fc,29"
"""
from __future__ import annotations

import re
import struct
import sys
from pathlib import Path


def pe32_sections(data: bytes) -> tuple[int, list[tuple[str, int, int, int, int]]]:
    e = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e : e + 4] != b"PE\0\0":
        raise SystemExit("not PE")
    nsec = struct.unpack_from("<H", data, e + 6)[0]
    soh = struct.unpack_from("<H", data, e + 0x14)[0]
    if struct.unpack_from("<H", data, e + 0x18)[0] != 0x10B:
        raise SystemExit("need PE32 (use x32dbg)")

    image_base = struct.unpack_from("<I", data, e + 0x18 + 0x1C)[0]
    sec0 = e + 0x18 + soh
    rows = []
    for i in range(nsec):
        s = sec0 + i * 0x28
        name = data[s : s + 8].split(b"\x00", 1)[0].decode("ascii", errors="replace")
        vsize, vaddr, rsize, raw = struct.unpack_from("<IIII", data, s + 8)
        rows.append((name, vaddr, vsize, raw, rsize))
    return image_base, rows


def fileoff_to_rva(sections, fo: int) -> int | None:
    for _, vaddr, _vsize, raw, rsize in sections:
        if rsize and raw <= fo < raw + rsize:
            return vaddr + (fo - raw)
    return None


def main() -> None:
    if len(sys.argv) < 3:
        print("usage: pe_bfind.py <exe> <hex,with,commas,or,spaces,or,none>", file=sys.stderr)
        raise SystemExit(2)
    path = Path(sys.argv[1])
    h = re.sub(r"[^0-9A-Fa-f]+", "", sys.argv[2])
    if len(h) % 2:
        print("odd hex", file=sys.stderr)
        raise SystemExit(1)
    needle = bytes.fromhex(h)
    data = path.read_bytes()
    ib, sections = pe32_sections(data)
    pos = 0
    out = 0
    while True:
        i = data.find(needle, pos)
        if i < 0:
            break
        rva = fileoff_to_rva(sections, i)
        va = ib + rva if rva is not None else None
        print(f"at file {i:#x}  rva {rva:#x} if in sec  |  va {f'{va:#x}' if va else 'n/a'}")

        if va is not None and out < 1:
            print("  x32dbg: bp {:#x}  (if game loads with image base 0x400000)".format(va), file=sys.stderr)
        out += 1
        pos = i + 1
    if not out:
        print("not found", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
