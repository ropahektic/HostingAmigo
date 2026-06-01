#!/usr/bin/env python3
"""Analyze WA game captures: Rbot jsonl or vanilla pcap/pcapng from W11.

Installed on CT 104 at /opt/WormNETBot/scripts/wa_analyze_capture.py

Examples:
  wa_analyze_capture.py list
  wa_analyze_capture.py list --incoming
  wa_analyze_capture.py endgame captures/incoming/red-blue-surrender.pcapng
  wa_analyze_capture.py endgame captures/20260528T073236Z-rank.jsonl
  wa_analyze_capture.py import-pcap captures/incoming/foo.pcapng --label vanilla-red-surrender
"""
from __future__ import annotations

import argparse
import json
import re
import struct
import subprocess
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CAPTURES = ROOT / "captures"
INCOMING = CAPTURES / "incoming"
IMPORTED = CAPTURES / "imported"

WA_PREFIX = struct.Struct("<BBH")
WA_GAME_REST = struct.Struct("<BI")
GAME_CHANNEL = 0x02
ENDGAME_MARKERS = (
    b"\x40\x06\x00",
    b"\xc0\x0d",
    b"\x40\x02\x04",
    b"\x40\x1e",
    b"\x64\x1e",
    b"\x50\x02",
    b"\x44\x02",
    b"\x78\x02",
    b"\x7c\x02",
)


def _is_endgame_body(body: bytes) -> bool:
    if not body:
        return False
    if body == b"\x40\x06\x00" or body.startswith(b"\xc0\x0d"):
        return True
    return body.startswith(ENDGAME_MARKERS)


def load_jsonl(path: Path) -> list[dict]:
    rows: list[dict] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


def endgame_timeline_jsonl(rows: list[dict]) -> list[dict]:
    out: list[dict] = []
    for row in rows:
        if row.get("type") != "packet" or row.get("channel") != 2:
            continue
        body_hex = row.get("body_hex") or ""
        try:
            body = bytes.fromhex(body_hex)
        except ValueError:
            continue
        if not _is_endgame_body(body):
            continue
        out.append(
            {
                "ts": row.get("ts"),
                "direction": row.get("direction"),
                "nickname": row.get("nickname"),
                "peer": row.get("peer"),
                "command": row.get("command"),
                "frame": row.get("frame"),
                "body_hex": body_hex,
                "body_preview": body[:12].hex(),
            }
        )
    return out


def _parse_wa_frames_from_buffer(buf: bytes, meta: dict) -> list[dict]:
    """Parse concatenated WA TCP payloads (one direction of one stream)."""
    frames: list[dict] = []
    offset = 0
    while offset + WA_PREFIX.size <= len(buf):
        channel, _unk, total_len = WA_PREFIX.unpack_from(buf, offset)
        if total_len < WA_PREFIX.size or offset + total_len > len(buf):
            break
        packet = buf[offset : offset + total_len]
        offset += total_len
        if channel != GAME_CHANNEL:
            continue
        if len(packet) < WA_PREFIX.size + WA_GAME_REST.size:
            continue
        rest_off = WA_PREFIX.size
        wire_id, frame = WA_GAME_REST.unpack_from(packet, rest_off)
        body = packet[rest_off + WA_GAME_REST.size :]
        if not _is_endgame_body(body):
            continue
        frames.append(
            {
                **meta,
                "command": wire_id,
                "frame": frame,
                "body_hex": body.hex(),
                "body_preview": body[:12].hex(),
            }
        )
    return frames


def _tshark_payload_rows(pcap: Path) -> list[dict]:
    cmd = [
        "tshark",
        "-r",
        str(pcap),
        "-Y",
        "tcp.port==17011 && tcp.payload",
        "-T",
        "fields",
        "-E",
        "separator=\t",
        "-e",
        "frame.time_epoch",
        "-e",
        "ip.src",
        "-e",
        "tcp.srcport",
        "-e",
        "ip.dst",
        "-e",
        "tcp.dstport",
        "-e",
        "tcp.stream",
        "-e",
        "tcp.payload",
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    except FileNotFoundError:
        print("error: tshark not installed (apt install tshark)", file=sys.stderr)
        sys.exit(1)
    if proc.returncode != 0 and not proc.stdout.strip():
        print(proc.stderr or "tshark failed", file=sys.stderr)
        sys.exit(1)

    rows: list[dict] = []
    for line in proc.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) < 7:
            continue
        epoch_s, src_ip, src_port, dst_ip, dst_port, stream, payload_hex = parts[:7]
        payload_hex = payload_hex.replace(":", "").strip()
        if not payload_hex:
            continue
        try:
            payload = bytes.fromhex(payload_hex)
        except ValueError:
            continue
        rows.append(
            {
                "epoch": float(epoch_s),
                "src_ip": src_ip,
                "src_port": int(src_port),
                "dst_ip": dst_ip,
                "dst_port": int(dst_port),
                "stream": int(stream),
                "payload": payload,
            }
        )
    return rows


def endgame_timeline_pcap(pcap: Path) -> list[dict]:
    raw_rows = _tshark_payload_rows(pcap)
    if not raw_rows:
        return []

    t0 = min(r["epoch"] for r in raw_rows)
    by_stream: dict[int, bytearray] = defaultdict(bytearray)
    stream_meta: dict[int, dict] = {}

    for row in raw_rows:
        stream = row["stream"]
        by_stream[stream] += row["payload"]
        if stream not in stream_meta:
            stream_meta[stream] = {
                "stream": stream,
                "src_ip": row["src_ip"],
                "src_port": row["src_port"],
                "dst_ip": row["dst_ip"],
                "dst_port": row["dst_port"],
            }

    events: list[dict] = []
    for stream, buf in by_stream.items():
        meta = stream_meta[stream]
        for fr in _parse_wa_frames_from_buffer(bytes(buf), meta):
            fr["direction"] = "pcap"
            fr["rel_s"] = None
            events.append(fr)

    events.sort(key=lambda e: (e.get("frame") or 0, e.get("stream") or 0))
    return events


def print_timeline(events: list[dict], *, source: str) -> None:
    print(f"=== endgame timeline: {source} ({len(events)} frames) ===")
    if not events:
        print("(no endgame-class channel-2 bodies found)")
        return
    t_first_json = None
    for ev in events:
        ts = ev.get("ts")
        if ts and t_first_json is None:
            t_first_json = ts
        parts = [
            str(ev.get("ts") or "")[-12:] if ev.get("ts") else f"stream={ev.get('stream')}",
            str(ev.get("direction") or "pcap"),
            f"wire={ev.get('command')}",
            f"frame=0x{int(ev.get('frame') or 0):08X}",
            str(ev.get("nickname") or ev.get("src_ip") or "?"),
            str(ev.get("body_preview") or ev.get("body_hex", "")[:24]),
        ]
        print("  " + " | ".join(p for p in parts if p))


def cmd_list(args: argparse.Namespace) -> int:
    dirs = [CAPTURES]
    if args.incoming:
        dirs = [INCOMING, IMPORTED, CAPTURES]
    seen: set[Path] = set()
    for d in dirs:
        if not d.is_dir():
            continue
        print(f"\n{d}/")
        files = sorted(
            list(d.glob("*.jsonl")) + list(d.glob("*.pcap")) + list(d.glob("*.pcapng")),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        for path in files[: args.limit]:
            if path in seen:
                continue
            seen.add(path)
            size_kb = path.stat().st_size // 1024
            mtime = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc).strftime(
                "%Y-%m-%d %H:%M UTC"
            )
            print(f"  {path.name:48} {size_kb:5} KB  {mtime}")
    return 0


def cmd_endgame(args: argparse.Namespace) -> int:
    path = Path(args.path)
    if not path.is_file():
        print(f"not found: {path}", file=sys.stderr)
        return 1
    suffix = path.suffix.lower()
    if suffix == ".jsonl":
        events = endgame_timeline_jsonl(load_jsonl(path))
    elif suffix in (".pcap", ".pcapng"):
        events = endgame_timeline_pcap(path)
    else:
        print(f"unsupported format: {suffix}", file=sys.stderr)
        return 1
    print_timeline(events, source=str(path))
    return 0


def cmd_import_pcap(args: argparse.Namespace) -> int:
    src = Path(args.path)
    if not src.is_file():
        print(f"not found: {src}", file=sys.stderr)
        return 1
    IMPORTED.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    label = re.sub(r"[^a-zA-Z0-9._-]+", "-", args.label or src.stem).strip("-") or "import"
    dest = IMPORTED / f"{stamp}-{label}.pcapng"
    if src.suffix.lower() != ".pcapng":
        dest = dest.with_suffix(src.suffix.lower())
    dest.write_bytes(src.read_bytes())

    events = endgame_timeline_pcap(dest)
    sidecar = dest.with_suffix(dest.suffix + ".meta.json")
    sidecar.write_text(
        json.dumps(
            {
                "imported_from": str(src),
                "imported_at": stamp,
                "label": label,
                "note": args.note or "",
                "endgame_frame_count": len(events),
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"imported -> {dest}")
    print_timeline(events, source=str(dest))
    return 0


def cmd_info(args: argparse.Namespace) -> int:
    path = Path(args.path)
    if path.suffix.lower() in (".pcap", ".pcapng"):
        cmd = ["tshark", "-r", str(path), "-q", "-z", "io,stat,0"]
        subprocess.run(cmd, check=False)
        cmd2 = [
            "tshark",
            "-r",
            str(path),
            "-Y",
            "tcp.port==17011",
            "-T",
            "fields",
            "-e",
            "tcp.stream",
            "-e",
            "ip.src",
            "-e",
            "tcp.srcport",
            "-e",
            "ip.dst",
            "-e",
            "tcp.dstport",
        ]
        proc = subprocess.run(cmd2, capture_output=True, text=True, check=False)
        print("=== tcp streams on port 17011 ===")
        streams: dict[str, set] = defaultdict(set)
        for line in proc.stdout.splitlines():
            parts = line.split("\t")
            if len(parts) >= 5:
                streams[parts[0]].add((parts[1], parts[2], parts[3], parts[4]))
        for stream, endpoints in sorted(streams.items(), key=lambda x: int(x[0])):
            print(f"  stream {stream}: {endpoints}")
    else:
        rows = load_jsonl(path)
        types = Counter = __import__("collections").Counter(r.get("type") for r in rows)
        print(f"jsonl records: {len(rows)} types={dict(types)}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="WA capture analyzer (jsonl + pcap)")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_list = sub.add_parser("list", help="List capture files")
    p_list.add_argument("--incoming", action="store_true", help="Show incoming/ and imported/")
    p_list.add_argument("--limit", type=int, default=20)
    p_list.set_defaults(func=cmd_list)

    p_end = sub.add_parser("endgame", help="Print endgame C2 timeline")
    p_end.add_argument("path", help="Path to .jsonl, .pcap, or .pcapng")
    p_end.set_defaults(func=cmd_endgame)

    p_imp = sub.add_parser("import-pcap", help="Copy pcap into captures/imported/ and summarize")
    p_imp.add_argument("path", help="Source pcap (e.g. captures/incoming/foo.pcapng)")
    p_imp.add_argument("--label", default="", help="Short label for filename")
    p_imp.add_argument("--note", default="", help="Free-text note stored in .meta.json")
    p_imp.set_defaults(func=cmd_import_pcap)

    p_info = sub.add_parser("info", help="Quick pcap/jsonl summary")
    p_info.add_argument("path")
    p_info.set_defaults(func=cmd_info)

    args = parser.parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
