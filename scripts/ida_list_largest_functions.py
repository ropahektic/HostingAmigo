# Run in IDA: File -> Script file… (if your IDA has IDAPython).
# If the dialog only offers .idc: use ida_list_largest_functions.idc (dumps all .text
# functions; sort by size in Excel; the .py version keeps top-400 in one step).
#
# Writes ida_largest_functions.txt next to the .idb (largest .text functions first).
#
# Edit TOP_N or TEXT_SEG if the script errors (section name: View -> Open subviews -> Segments).
from __future__ import annotations

import os

OUT_NAME = "ida_largest_functions.txt"
TOP_N = 400
TEXT_SEG = ".text"

try:
    import ida_funcs
    import ida_segment
    import idaapi
    import idautils
    import idc
except ImportError as e:
    raise SystemExit("This script only runs inside IDA (IDAPython).") from e


def _seg_name(ea: int) -> str:
    s = ida_segment.getseg(ea)
    if not s:
        return ""
    return idaapi.get_segm_name(s) or ""


def _out_path() -> str:
    # idb path is next to the database; good place for a small report
    p = getattr(idc, "get_idb_path", lambda: None)() or "."
    d = os.path.dirname(p) or "."
    return os.path.join(d, OUT_NAME)


def main() -> None:
    rows: list[tuple[int, int, int, str]] = []
    for start in idautils.Functions():
        f = ida_funcs.get_func(start)
        if not f:
            continue
        if _seg_name(start) != TEXT_SEG:
            continue
        name = idc.get_func_name(start) or f"sub_{start:08X}"
        size = int(f.end_ea - f.start_ea)
        if size > 0:
            rows.append((size, int(f.start_ea), int(f.end_ea), name))
    rows.sort(key=lambda t: -t[0])
    path = _out_path()
    n = min(TOP_N, len(rows))
    text = (
        f"# nfunctions={len(rows)}  top={n}  segment={TEXT_SEG!r}\n"
        f"# size\tstart\tend\tname\n"
    )
    for t in rows[:TOP_N]:
        text += f"0x{t[0]:08X}\t0x{t[1]:08X}\t0x{t[2]:08X}\t{t[3]}\n"
    with open(path, "w", encoding="utf-8", newline="\n") as out:
        out.write(text)
    print(f"Wrote {n} lines -> {path}")


if __name__ == "__main__":
    main()
