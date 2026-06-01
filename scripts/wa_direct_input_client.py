#!/usr/bin/env python3
"""
In-process WA.exe control via Frida (no SendInput to the game for fire — uses NativeFunction).

1) Get **control_rope (or your method) RVA** from retail IDA.
2) **Pointer discovery:**  python3 ... --sniff 0xYOUR_RVA
   Play with rope; each line on stdout is one `this` (ECX) seen on entry. Use the last stable
   value (same worm/turn) for --set-this, or use getLastThiscallThis in Frida REPL.
3) **Fire:** --set-rva, --set-this, --fire  OR  keep process attached and:
   python3 ... --set-rva ... --set-this ... --bind '<f9>'

**Hotkey (optional):** pip install pynput. Uses global hotkey — default recommend '<f9>' or
'<ctrl>+<shift>+z>'. A bare '<z>' may interfere with other apps; use at your own risk.

Requires: pip install frida frida-tools
Optional: pip install pynput
"""
from __future__ import annotations

import argparse
import json
import signal
import sys
from pathlib import Path
from typing import Any, Callable

try:
    import frida
except ImportError as exc:  # pragma: no cover
    raise SystemExit("Install frida: pip install frida frida-tools") from exc


def _load_js() -> str:
    p = Path(__file__).resolve().parent / "wa_direct_input_frida.js"
    return p.read_text(encoding="utf-8")


def _make_on_message(
    print_sniff: bool, print_load: bool
) -> Callable[[Any, bytes], None]:
    def _on_message(message: object, _data: bytes) -> None:
        if not isinstance(message, dict):
            return
        t = message.get("type")
        if t == "error":
            print(message, file=sys.stderr)
        elif t == "send" and print_sniff:
            pl = message.get("payload", message)
            if (
                isinstance(pl, dict)
                and pl.get("sniff")
                and "thiscall_this" in pl
            ):
                print(str(pl["thiscall_this"]).strip(), flush=True)
        elif t == "send" and print_load:
            pl = message.get("payload", message)
            if isinstance(pl, dict) and pl.get("loaded"):
                print("[script]", json.dumps(pl), file=sys.stderr)

    return _on_message


def _attach(name: str) -> frida.core.Session:
    try:
        return frida.attach(name)
    except frida.ProcessNotFoundError as exc:  # pragma: no cover
        raise SystemExit(f"Not running: {name}") from exc


def _run_sniff(_args: argparse.Namespace) -> int:
    session = _attach(_args.target)
    script = session.create_script(_load_js())
    script.on("message", _make_on_message(True, True))
    script.load()
    exp = script.exports_sync
    out = exp.start_sniff(_args.sniff)
    print("startSniff", json.dumps(out, indent=2), file=sys.stderr)
    if isinstance(out, dict) and not out.get("ok"):
        return 2
    print(
        "Lines on stdout: this (ECX) per call. Move rope, attach, use rope. Ctrl+C to stop.",
        file=sys.stderr,
    )

    def on_sigint(_a: int, _b: object) -> None:  # pragma: no cover
        exp.stop_sniff()
        sys.exit(0)

    signal.signal(signal.SIGINT, on_sigint)
    import time

    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:  # pragma: no cover
        pass
    finally:
        exp.stop_sniff()
    return 0


def _run_hotkey(args: argparse.Namespace) -> int:
    try:
        from pynput import keyboard
    except ImportError as exc:  # pragma: no cover
        raise SystemExit("Hotkey mode needs: pip install pynput") from exc

    session = _attach(args.target)
    script = session.create_script(_load_js())
    script.on("message", _make_on_message(False, True))
    script.load()
    exp = script.exports_sync
    if args.set_rva:
        print("CONTROL_ROPE_RVA", exp.set_control_rope_rva(args.set_rva), file=sys.stderr)
    if args.set_this:
        print("TASK_WORM_THIS", exp.set_task_worm_this(args.set_this), file=sys.stderr)
    if args.repeats != 3 or args.delay_ms:
        print("rapid", exp.set_rapid(args.repeats, args.delay_ms), file=sys.stderr)
    if not args.set_rva or not args.set_this:
        print(
            "Warning: for useful bursts, set both --set-rva and --set-this before playing.",
            file=sys.stderr,
        )

    def fire() -> None:
        out = exp.fire_rope_burst()
        line = json.dumps(out)
        print(f"[fire] {line}", flush=True)

    spec = args.bind
    assert spec is not None
    hot: dict[str, Callable[[], None]] = {spec: fire}
    listener = keyboard.GlobalHotKeys(hot)
    listener.start()
    print(
        f"Global hotkey {spec!r} -> fireRopeBurst (in-process, not key-to-WA). Ctrl+C to exit.",
        file=sys.stderr,
    )
    try:
        listener.join()
    except KeyboardInterrupt:  # pragma: no cover
        pass
    finally:
        listener.stop()
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description="In-process Frida control for WA.exe (see docstring).",
    )
    ap.add_argument("--target", default="WA.exe", help="Process name to attach")
    ap.add_argument("--ping", action="store_true", help="Print image base and exit")
    ap.add_argument("--set-rva", metavar="HEX", help="control_rope (or method) RVA")
    ap.add_argument(
        "--set-this",
        metavar="HEX",
        help="Task_Worm* from sniff / CE (must match current worm/turn for reliable burst)",
    )
    ap.add_argument(
        "--fire", action="store_true", help="Call fireRopeBurst once, then exit"
    )
    ap.add_argument(
        "--sniff",
        metavar="HEX",
        help="Log thiscall `this' (one hex per line on stdout) while the game hits this RVA. "
        "Get RVA from IDA. Play with rope after starting.",
    )
    ap.add_argument(
        "--bind",
        metavar="HOTKEY",
        help="Run until Ctrl+C. pynput hotkey, e.g. '<f9>' or '<ctrl>+<shift>+z>'."
        " Pair with --set-rva and --set-this. Not SendInput to WA — fires Frida only.",
    )
    ap.add_argument("--repeats", type=int, default=3, metavar="N")
    ap.add_argument("--delay-ms", type=int, default=0, metavar="MS")
    args = ap.parse_args()

    if args.sniff:
        return _run_sniff(args)

    if args.bind is not None:
        return _run_hotkey(args)

    session = _attach(args.target)
    script = session.create_script(_load_js())
    script.on("message", _make_on_message(False, True))
    script.load()

    exp = script.exports_sync
    if args.ping:
        print("base", exp.get_base())
        return 0

    if args.set_rva:
        print("CONTROL_ROPE_RVA", exp.set_control_rope_rva(args.set_rva))
    if args.set_this:
        print("TASK_WORM_THIS", exp.set_task_worm_this(args.set_this))
    if args.repeats != 3 or args.delay_ms:
        print("rapid", exp.set_rapid(args.repeats, args.delay_ms))

    if args.fire:
        out = exp.fire_rope_burst()
        print(json.dumps(out, indent=2))
        if isinstance(out, dict) and not out.get("ok"):
            return 2
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
