#!/usr/bin/env python3
"""Print ImageBase, Entry, sections for a PE32 exe (e.g. WA Updated.exe in repo root)."""
from __future__ import annotations

import struct
import sys
from pathlib import Path


def main() -> int:
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent / "WA Updated.exe"
    data = path.read_bytes()
    e = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e : e + 4] != b"PE\0\0":
        print("not PE", file=sys.stderr)
        return 1
    soh = struct.unpack_from("<H", data, e + 0x14)[0]
    opt = e + 0x18
    magic = struct.unpack_from("<H", data, opt)[0]
    if magic != 0x10B:
        print("not PE32", file=sys.stderr)
        return 1
    image_base = struct.unpack_from("<I", data, opt + 0x1C)[0]
    entry_rva = struct.unpack_from("<I", data, opt + 0x10)[0]
    nsec = struct.unpack_from("<H", data, e + 6)[0]
    sec0 = e + 0x18 + soh
    print("file", path)
    print("size", len(data))
    print("image_base_pe_header", hex(image_base))
    print("entry_rva", hex(entry_rva))
    print("entry_va_if_base_as_in_header", hex(image_base + entry_rva))
    print("sections", nsec)
    for i in range(min(nsec, 8)):
        s = sec0 + i * 0x28
        name = data[s : s + 8].split(b"\x00", 1)[0].decode("ascii", errors="replace")
        vsize, vaddr, rsize, raw = struct.unpack_from("<IIII", data, s + 8)
        print(" ", name, "vaddr", hex(vaddr), "vsize", hex(vsize), "raw", hex(raw))
    print("note: if Frida/loader shows a different image base (e.g. 0x320000), RVAs in the file are")
    print("  still the same: runtime_addr = your_module_base + rva  (rva = addr_in_ida - imagebase_used_in_ida)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
