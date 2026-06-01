from __future__ import annotations

import argparse
import socket
import struct
import sys
import time
from collections import deque
from typing import Iterable


LOBBY_CHANNEL = 0x01
GAME_CHANNEL = 0x02

CMD_LOGIN = 0x04
CMD_LOGIN2 = 0x05
CMD_READY = 0x0F
CMD_TEAM_ADD = 0x1A
SRV_PLAYER_LIST = 0x0B
SRV_TEAM_LIST = 0x0C
# After LOGIN2, real hosts often send 0x0B roster, then 0x0C teams, 0x1F scheme, 0x21 map.
# CMD_READY sent on the first 0x0B alone is often ignored or overwritten; wait for 0x21.
SRV_RANDOM_MAP = 0x21
SRV_START_GAME = 0x1C

# SRV_START_GAME (0x1C) lobby body matches game_host._pack_start_game / ``network protocol`` "Starting Game":
# u16 pad, u32 logic_seed (host echo of session seed; real WA ties to registry LogicSeed), b"GSAW", u32 game_ver.
SRV_START_GAME_BODY = struct.Struct("<HI4sI")

# Post-0x1C: game channel (0x02) loading frames 1..0x1A then frame 0x0200001B (game_host calls this loading "0x1A"
# family; wire frame number is 0x0200001B). The 0x0200001B body is the "magic" / checksum over map + worms +
# logic derived from the start packet — wrong bytes => invalid data / kick. ``network protocol``: best bet is
# to sniff another human's 0x0200001B and echo the same payload (wa_probe default). RBot single-client setups
# rely on relaying that one client's magic (no second peer to sniff on the wire).
LOADING_BODY_TAG = 0x0AC0
LOADING_FRAME_FIRST = 1
LOADING_FRAME_LAST = 0x1A
LOADING_DONE_FRAME = 0x0200001B
# Last-resort only when no peer sends 0x0200001B before sniff timeout (almost never valid vs real LogicSeed).
DEFAULT_LOADING_DONE_BODY = bytes.fromhex("40 09 65 e1 0f 8d 00")

# wa_playerlist + wa_team_list (wabs include/worms/wa-protocol.h); same TEAM body for 0x0C and 0x1A.
PLAYER_LIST_PREFIX = 6
PLAYER_NAME_SIZE = 17
PLAYER_STRUCT_SIZE = 120
PLAYER_SLOT_COUNT = 7
TEAM_STRUCT_SIZE = 3458

WA_PACKET_PREFIX = struct.Struct("<BBH")
WA_LOBBY_REST = struct.Struct("<BB")
WA_GAME_REST = struct.Struct("<BI")

# Default TCP join (WormNET listing). Override with --host / --game-id / --game-name.
DEFAULT_HOST = ""
DEFAULT_GAME_ID = "128" 


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


def pack_cmd_ready(*, player_id: int, ready: bool) -> bytes:
    """Client CMD_READY (0x0F): 10-byte body; joiners usually use player_id=1 (local self)."""
    payload = struct.pack("<HII", 0, 1 if ready else 0, player_id)
    return pack_lobby(CMD_READY, payload)


def pack_cmd_team_add(body: bytes) -> bytes:
    """Client CMD_TEAM_ADD (0x1A): same 3458-byte team blob shape as SRV_TEAM_LIST (0x0C), per wabs."""
    return pack_lobby(CMD_TEAM_ADD, body)


def pack_game_frame(*, wire_player_id: int, frame: int, payload: bytes, unknown: int = 0) -> bytes:
    """Game channel (0x02) frame: prefix + player byte + frame u32 + body (matches game_host.WA_FRAME_HEADER)."""
    total = WA_PACKET_PREFIX.size + WA_GAME_REST.size + len(payload)
    return (
        WA_PACKET_PREFIX.pack(GAME_CHANNEL, unknown, total)
        + WA_GAME_REST.pack(wire_player_id & 0xFF, frame & 0xFFFFFFFF)
        + payload
    )


def pack_loading_frame(*, wire_player_id: int, frame: int) -> bytes:
    inner = struct.pack("<HH", LOADING_BODY_TAG, (frame - 1) * 4)
    return pack_game_frame(wire_player_id=wire_player_id, frame=frame, payload=inner)


def send_loading_frames_only(sock: socket.socket, *, wire_player_id: int) -> None:
    for frame in range(LOADING_FRAME_FIRST, LOADING_FRAME_LAST + 1):
        sock.sendall(pack_loading_frame(wire_player_id=wire_player_id, frame=frame))
    print(
        f"sent game loading frames {LOADING_FRAME_FIRST}..0x{LOADING_FRAME_LAST:X} "
        f"(wire_player_id={wire_player_id})",
        flush=True,
    )


def parse_srv_start_game(body: bytes) -> tuple[int, bytes, int] | None:
    """Return (logic_seed, gsaw_tag, game_version) from 0x1C payload, or None if too short."""
    if len(body) < SRV_START_GAME_BODY.size:
        return None
    _pad, logic_seed, gsaw_tag, game_ver = SRV_START_GAME_BODY.unpack_from(body, 0)
    return logic_seed, gsaw_tag, game_ver


def send_loading_done_only(sock: socket.socket, *, wire_player_id: int, done_body: bytes) -> None:
    sock.sendall(
        pack_game_frame(wire_player_id=wire_player_id, frame=LOADING_DONE_FRAME, payload=done_body)
    )
    print(
        f"sent game loading-done 0x{LOADING_DONE_FRAME:08X} (wire_player_id={wire_player_id}) "
        f"body={done_body.hex(' ')}",
        flush=True,
    )


def recv_all_before_deadline(sock: socket.socket, n: int, deadline: float) -> bytes:
    """Read exactly ``n`` bytes or raise TimeoutError / ConnectionError."""
    buf = b""
    while len(buf) < n:
        remaining_time = deadline - time.monotonic()
        if remaining_time <= 0:
            raise TimeoutError
        sock.settimeout(min(30.0, remaining_time))
        try:
            chunk = sock.recv(n - len(buf))
        except socket.timeout:
            raise TimeoutError
        if not chunk:
            raise ConnectionError("socket closed")
        buf += chunk
    return buf


def recv_one_packet(sock: socket.socket, *, deadline: float | None) -> tuple[int, int, int, bytes]:
    """One WA packet from ``sock``. If ``deadline`` is set, raises TimeoutError while waiting for data."""
    if deadline is None:
        prefix = recv_exact(sock, WA_PACKET_PREFIX.size)
    else:
        prefix = recv_all_before_deadline(sock, WA_PACKET_PREFIX.size, deadline)
    channel, unknown, packet_len = WA_PACKET_PREFIX.unpack(prefix)
    rest_len = packet_len - WA_PACKET_PREFIX.size
    if deadline is None:
        rest = recv_exact(sock, rest_len)
    else:
        rest = recv_all_before_deadline(sock, rest_len, deadline)
    if channel == LOBBY_CHANNEL:
        command, pad = WA_LOBBY_REST.unpack(rest[: WA_LOBBY_REST.size])
        body = rest[WA_LOBBY_REST.size :]
        return channel, command, pad, body
    if channel == GAME_CHANNEL:
        player_id, frame = WA_GAME_REST.unpack(rest[: WA_GAME_REST.size])
        body = rest[WA_GAME_REST.size :]
        return channel, player_id, frame, body
    body = rest
    return channel, unknown, packet_len, body


def sniff_peer_loading_done_body(
    sock: socket.socket,
    *,
    self_wire: int,
    replay: deque[tuple[int, int, int, bytes]],
    deadline: float,
) -> bytes | None:
    """Capture another human's loading-done (logic checksum / magic) body; queue other packets into ``replay``."""
    while time.monotonic() < deadline:
        try:
            pkt = recv_one_packet(sock, deadline=deadline)
        except TimeoutError:
            return None
        ch, wire, frame, body = pkt
        if ch == GAME_CHANNEL and frame == LOADING_DONE_FRAME and wire != self_wire:
            print(
                f"(sniff) peer loading-done wire={wire} frame=0x{frame:08X} body={body.hex(' ')}",
                flush=True,
            )
            return body
        replay.append(pkt)
    return None


def decode_c_string(buf: bytes) -> str:
    end = buf.find(b"\x00")
    if end < 0:
        end = len(buf)
    return buf[:end].decode("latin-1", errors="replace")


def roster_player_id_for_nick(lobby_body: bytes, nick: str) -> int | None:
    """Map global roster slot index (0..6) from last SRV_PLAYER_LIST body."""
    if len(lobby_body) < PLAYER_LIST_PREFIX + PLAYER_NAME_SIZE:
        return None
    for slot in range(PLAYER_SLOT_COUNT):
        off = PLAYER_LIST_PREFIX + slot * PLAYER_STRUCT_SIZE
        if off + PLAYER_NAME_SIZE > len(lobby_body):
            break
        if decode_c_string(lobby_body[off : off + PLAYER_NAME_SIZE]) == nick:
            return slot
    return None


def pick_unclaimed_team_template(team_bodies: list[bytes]) -> bytes | None:
    """First full team row with server player_id 0 (open seat / template) from latest snapshot."""
    for body in team_bodies:
        if len(body) == TEAM_STRUCT_SIZE and body[6] == 0:
            return body
    return None


def team_claim_payload_from_server_row(template: bytes, roster_player_id: int | None) -> bytes:
    """Clone host 0x0C row and bind owner byte (offset 6) so the host accepts the joiner on that team."""
    row = bytearray(template)
    pid = roster_player_id if roster_player_id is not None else 1
    row[6] = pid & 0xFF
    return bytes(row)


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


def iter_packets(
    sock: socket.socket, replay: deque[tuple[int, int, int, bytes]] | None = None
) -> Iterable[tuple[int, int, int, bytes]]:
    q = replay if replay is not None else deque()
    while True:
        if q:
            yield q.popleft()
            continue
        yield recv_one_packet(sock, deadline=None)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Join a WA TCP lobby and print raw packets (channel 0x01 / 0x02).",
        epilog=(
            "WormNET / wa:// listed games: put the ID query value in --game-id (e.g. wa://host?...&ID=123 → "
            "--game-id 123). Wrong or default game strings make a real WA host answer 0x27 (game id wrong) "
            "or 0x2E before 0x08; you will never get LOGIN2 / lobby traffic. Plain IP games often use an "
            "empty --game-name.\n"
            "Real hosts need CMD_READY with the joiner's global roster id in the packet (not local 1): "
            "--auto-ready parses your slot from the last 0x0B nick match. After 0x21, --auto-ready-delay "
            "waits before sending (a new join clears everyone else's ready; sending too early is ignored). "
            "Spectators do not need a team if others already have teams; use --auto-team for CMD_TEAM_ADD. "
            "RBot maps ready by TCP; use --ready-local-self there.\n"
            "After 0x1C the host sends logic_seed + GSAW + version (see printed line). Each client then sends "
            "game-channel loading 1..0x1A; frame 0x0200001B carries session magic (checksum on map/worms/logic). "
            "By default we sniff a peer's 0x0200001B body and echo it (same as network protocol / RBot relay). "
            "Solo-WA vs RBot has no second peer — use RBot's relay or --loading-done-hex from a capture. "
            "Disable loading with --no-auto-load."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--host", default=DEFAULT_HOST, help=f"TCP host (default {DEFAULT_HOST})")
    parser.add_argument("--port", type=int, default=17011)
    parser.add_argument("--nick", default="probe")
    parser.add_argument("--game-name", default="", help="LOGIN game id string (often empty for raw IP games)")
    parser.add_argument(
        "--game-id",
        default=DEFAULT_GAME_ID,
        help=f"If non-empty, overrides --game-name (default {DEFAULT_GAME_ID!r} for current listing)",
    )
    parser.add_argument("--country", type=int, default=15)
    parser.add_argument(
        "--auto-ready",
        action="store_true",
        help=(
            "After LOGIN2, on first SRV_RANDOM_MAP (0x21): send CMD_READY using global roster id from 0x0B "
            "nick match, else --ready-player-id."
        ),
    )
    parser.add_argument(
        "--auto-team",
        action="store_true",
        help="With --auto-ready, also send CMD_TEAM_ADD (0x1A) cloned from first unclaimed 0x0C row (not needed for spectators).",
    )
    parser.add_argument(
        "--ready-player-id",
        type=int,
        default=1,
        help="With --ready-local-self: dword sent as-is. Else: fallback if nick not in last 0x0B.",
    )
    parser.add_argument(
        "--ready-local-self",
        action="store_true",
        help="With --auto-ready, always use --ready-player-id in CMD_READY (for RBot; real WA hosts need global roster id).",
    )
    parser.add_argument(
        "--auto-ready-delay",
        type=float,
        default=1.0,
        metavar="SEC",
        help="With --auto-ready, seconds to wait after first 0x21 before team add / CMD_READY (0 disables). Default 1.",
    )
    parser.add_argument(
        "--no-auto-load",
        action="store_true",
        help="Do not send game-channel loading handshake after 0x1C (otherwise others wait forever).",
    )
    parser.add_argument(
        "--game-local-self",
        action="store_true",
        help="Use wire player_id=1 on game channel (RBot); default is roster slot like real WA.",
    )
    parser.add_argument(
        "--game-wire-player-id",
        type=int,
        default=None,
        metavar="N",
        help="Force game-channel header player byte (overrides roster / --game-local-self).",
    )
    parser.add_argument(
        "--loading-done-hex",
        default="",
        metavar="HEX",
        help="If set, use this loading-done body and skip sniffing peers.",
    )
    parser.add_argument(
        "--loading-sniff-timeout",
        type=float,
        default=30.0,
        metavar="SEC",
        help="Max wait for a peer 0x0200001B magic body to echo (only without --loading-done-hex).",
    )
    args = parser.parse_args()

    game_name = args.game_id if args.game_id.strip() else args.game_name

    with socket.create_connection((args.host, args.port), timeout=10) as sock:
        sock.settimeout(None)
        print(f"connected to {args.host}:{args.port}", flush=True)
        sock.sendall(pack_login(args.nick, game_name))
        print(f"sent login nick={args.nick!r} game_name={game_name!r}", flush=True)

        login2_sent = False
        auto_ready_sent = False
        auto_load_sent = False
        last_roster: bytes | None = None
        last_parsed_roster: int | None = None
        team_rows_since_roster: list[bytes] = []
        replay: deque[tuple[int, int, int, bytes]] = deque()
        for channel, a, b, body in iter_packets(sock, replay):
            if channel == LOBBY_CHANNEL:
                print(f"lobby cmd=0x{a:02X} len={len(body)} body={body_preview(body)}", flush=True)
                if a == SRV_START_GAME:
                    parsed = parse_srv_start_game(body)
                    if parsed is not None:
                        logic_seed, gsaw_tag, game_ver = parsed
                        print(
                            f"  0x1C start: logic_seed=0x{logic_seed:08X} tag={gsaw_tag!r} "
                            f"game_ver=0x{game_ver:x} (loading-done magic must match this session)",
                            flush=True,
                        )
                if login2_sent and a == SRV_PLAYER_LIST:
                    last_roster = body
                    last_parsed_roster = roster_player_id_for_nick(body, args.nick)
                    team_rows_since_roster.clear()
                if login2_sent and a == SRV_TEAM_LIST and len(body) == TEAM_STRUCT_SIZE:
                    team_rows_since_roster.append(body)
                if a == 0x27 and not login2_sent:
                    print(
                        "hint: host sent 0x27 (game id incorrect). For wa://...&ID=N use --game-id N "
                        "(see --help).",
                        flush=True,
                    )
                if a == 0x08 and not login2_sent:
                    sock.sendall(pack_login2(args.nick, args.country))
                    login2_sent = True
                    print(f"sent login2 nick={args.nick!r} country={args.country}", flush=True)
                if (
                    args.auto_ready
                    and login2_sent
                    and not auto_ready_sent
                    and a == SRV_RANDOM_MAP
                ):
                    roster_id = (
                        roster_player_id_for_nick(last_roster, args.nick) if last_roster is not None else None
                    )
                    if roster_id is not None:
                        print(f"parsed roster slot for nick={args.nick!r} -> player_id={roster_id}", flush=True)
                    delay = max(0.0, args.auto_ready_delay)
                    if delay > 0:
                        print(
                            f"waiting {delay:g}s after 0x21 before auto-ready (join clears others' ready)",
                            flush=True,
                        )
                        time.sleep(delay)
                    if args.auto_team:
                        template = pick_unclaimed_team_template(team_rows_since_roster)
                        if template is not None:
                            claim = team_claim_payload_from_server_row(template, roster_id)
                            sock.sendall(pack_cmd_team_add(claim))
                            print(
                                "sent CMD_TEAM_ADD (0x1A) from unclaimed 0x0C row "
                                f"slot_u16={struct.unpack_from('<H', claim, 2)[0]} owner_byte={claim[6]}",
                                flush=True,
                            )
                        else:
                            print(
                                "warn: --auto-team set but no 0x0C row with player_id==0; skipping team add",
                                flush=True,
                            )
                    if args.ready_local_self:
                        ready_pid = args.ready_player_id
                    else:
                        ready_pid = roster_id if roster_id is not None else args.ready_player_id
                    pkt = pack_cmd_ready(player_id=ready_pid, ready=True)
                    sock.sendall(pkt)
                    auto_ready_sent = True
                    src = "ready-local-self" if args.ready_local_self else (
                        "roster" if roster_id is not None else "fallback"
                    )
                    print(f"sent CMD_READY ready=True player_id={ready_pid} ({src})", flush=True)
                if (
                    not args.no_auto_load
                    and login2_sent
                    and not auto_load_sent
                    and a == SRV_START_GAME
                ):
                    if args.game_wire_player_id is not None:
                        wpid = args.game_wire_player_id & 0xFF
                    elif args.game_local_self:
                        wpid = 1
                    else:
                        wpid = last_parsed_roster if last_parsed_roster is not None else 1
                    done_hex = (args.loading_done_hex or "").strip().replace(" ", "")
                    if done_hex:
                        done_body = bytes.fromhex(done_hex)
                        send_loading_frames_only(sock, wire_player_id=wpid)
                        send_loading_done_only(sock, wire_player_id=wpid, done_body=done_body)
                    else:
                        send_loading_frames_only(sock, wire_player_id=wpid)
                        sniff_deadline = time.monotonic() + max(0.1, args.loading_sniff_timeout)
                        done_body = sniff_peer_loading_done_body(
                            sock, self_wire=wpid, replay=replay, deadline=sniff_deadline
                        )
                        if done_body is None:
                            print(
                                "warn: no peer loading-done (0x0200001B magic) before timeout; using built-in "
                                "fallback (wrong vs logic_seed/session — expect kick). Solo: use RBot relay or "
                                "--loading-done-hex from a real client's capture.",
                                flush=True,
                            )
                            done_body = DEFAULT_LOADING_DONE_BODY
                        send_loading_done_only(sock, wire_player_id=wpid, done_body=done_body)
                    auto_load_sent = True
            elif channel == GAME_CHANNEL:
                print(f"game player={a} frame=0x{b:08X} len={len(body)} body={body_preview(body)}", flush=True)
            else:
                print(
                    f"other channel=0x{channel:02X} unk=0x{a:02X} pktlen={b} len={len(body)} "
                    f"body={body_preview(body)}",
                    flush=True,
                )

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        sys.exit(130)
