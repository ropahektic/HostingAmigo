from __future__ import annotations

import argparse
import socket
import struct
import sys
from typing import Iterable


LOBBY_CHANNEL = 0x01
GAME_CHANNEL = 0x02

CMD_LOGIN = 0x04
CMD_LOGIN2 = 0x05

WA_PACKET_PREFIX = struct.Struct("<BBH")
WA_LOBBY_REST = struct.Struct("<BB")
WA_GAME_REST = struct.Struct("<BI")


def encode_fixed_string(value: str, length: int) -> bytes:
    encoded = value.encode("latin-1", errors="replace")[:length]
    return encoded + (b"\x00" * (length - len(encoded)))


def body_preview(data: bytes, limit: int = 96) -> str:
    preview = data[:limit].hex(" ")
    if len(data) > limit:
        preview += f" ... (+{len(data) - limit} bytes)"
    return preview or "<empty>"


def pack_lobby(command: int, payload: bytes) -> bytes:
    packet_len = WA_PACKET_PREFIX.size + WA_LOBBY_REST.size + len(payload)
    return WA_PACKET_PREFIX.pack(LOBBY_CHANNEL, 0, packet_len) + WA_LOBBY_REST.pack(command, 0) + payload


def pack_login(nickname: str, game_name: str) -> bytes:
    payload = bytearray(122)
    payload[0:17] = encode_fixed_string(nickname, 17)
    payload[17:34] = encode_fixed_string(game_name, 17)
    payload[58:61] = bytes.fromhex("f4 25 f4")
    return pack_lobby(CMD_LOGIN, bytes(payload))


def pack_login2(nickname: str, country: int) -> bytes:
    payload = bytearray(108)
    payload[0:17] = encode_fixed_string(nickname, 17)
    payload[66] = country & 0xFF
    return pack_lobby(CMD_LOGIN2, bytes(payload))


def recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ConnectionError("socket closed")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def iter_packets(sock: socket.socket) -> Iterable[tuple[int, int, int, bytes]]:
    while True:
        prefix = recv_exact(sock, WA_PACKET_PREFIX.size)
        channel, unknown, packet_len = WA_PACKET_PREFIX.unpack(prefix)
        if channel == LOBBY_CHANNEL:
            rest = recv_exact(sock, WA_LOBBY_REST.size)
            command, pad = WA_LOBBY_REST.unpack(rest)
            body = recv_exact(sock, packet_len - WA_PACKET_PREFIX.size - WA_LOBBY_REST.size)
            yield channel, command, pad, body
        elif channel == GAME_CHANNEL:
            rest = recv_exact(sock, WA_GAME_REST.size)
            player_id, frame = WA_GAME_REST.unpack(rest)
            body = recv_exact(sock, packet_len - WA_PACKET_PREFIX.size - WA_GAME_REST.size)
            yield channel, player_id, frame, body
        else:
            raise RuntimeError(f"unknown channel 0x{channel:02X} unknown=0x{unknown:02X} len={packet_len}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Join a WA lobby and print raw packets.")
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, default=17011)
    parser.add_argument("--nick", default="probe")
    parser.add_argument("--game-name", default="probe")
    parser.add_argument("--country", type=int, default=15)
    args = parser.parse_args()

    with socket.create_connection((args.host, args.port), timeout=10) as sock:
        sock.settimeout(None)
        print(f"connected to {args.host}:{args.port}", flush=True)
        sock.sendall(pack_login(args.nick, args.game_name))
        print(f"sent login nick={args.nick!r} game={args.game_name!r}", flush=True)

        login2_sent = False
        for channel, a, b, body in iter_packets(sock):
            if channel == LOBBY_CHANNEL:
                print(f"lobby cmd=0x{a:02X} len={len(body)} body={body_preview(body)}", flush=True)
                if a == 0x08 and not login2_sent:
                    sock.sendall(pack_login2(args.nick, args.country))
                    login2_sent = True
                    print(f"sent login2 nick={args.nick!r} country={args.country}", flush=True)
            else:
                print(f"game player={a} frame=0x{b:08X} len={len(body)} body={body_preview(body)}", flush=True)

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        sys.exit(130)
