from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import random
import struct
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Awaitable, Callable, Iterable

from .config import BotConfig
from .endgame_net import EndgameNetState, EndgamePhase
from enum import Enum


class C2RelayPhase(Enum):
    """When RBot injects host (wire 0) traffic vs peer-only relay."""

    LOADING = "loading"  # Host c00a ladder + loading-done magic per client
    PASSIVE = "passive"  # Gameplay: relay humans only, no host GameNet injection
    ENDGAME = "endgame"  # End-of-match: re-enable host GameNet assist if needed
from .wa_endgame_c2 import is_endgame_fanfare_c2_body
from .wa_gamenet_handshake import (
    EndgameHandshakeAssist,
    DEFAULT_GAMENET_FRAME,
    gamenet_frame_for_host,
    host_mask_gamenet_body,
    is_gamenet_transport_body,
)
from .openwa_winner_sidecar import (
    clear_openwa_winner_sidecar,
    read_openwa_winner_sidecar,
    sidecar_path_from_config,
)
from .wa_task_stream import (
    EndgameTracker,
    announced_result_from_bodies,
    parse_c2_400204_wrappers,
    parse_surrender_announcements,
    parse_win_announcements,
    summarize_wire_re_gap,
)


LOGGER = logging.getLogger(__name__)

LOBBY_CHANNEL = 0x01
GAME_CHANNEL = 0x02

# WA.exe internal task-queue names (frame sync, checksum ticks, etc.) for RE / Frida correlation —
# not the same integers as channel-2 wire bodies or put_message TaskMessageType (often 1000+tag).
# See ``wa_engine_task_message.WaEngineTaskMessage`` and ``scripts/wa_serialization.py``.

CMD_CHAT = 0x00
CMD_LOGIN = 0x04
CMD_LOGIN2 = 0x05
CMD_READY = 0x0F
CMD_TEAM_REMOVE = 0x10
CMD_TEAM_COLOR = 0x16
CMD_TEAM_HANDICAP = 0x17
CMD_TEAM_WORMS = 0x18
CMD_TEAM_ADD = 0x1A

SRV_CHAT = 0x00
SRV_CUSTOM_SCHEME = 0x0D
SRV_LOGIN_OK = 0x08
SRV_LOGIN_ERROR = 0x0A
SRV_PLAYER_LIST = 0x0B
SRV_TEAM_LIST = 0x0C
SRV_PLAYER_JOIN = 0x0E
SRV_READY = 0x0F
SRV_TEAM_REMOVE = 0x10
SRV_TEAM_COLOR = 0x16
SRV_TEAM_HANDICAP = 0x17
SRV_TEAM_WORMS = 0x18
SRV_PLAYER_LEFT = 0x19
SRV_START_GAME = 0x1C
SRV_DEFAULT_SCHEME = 0x1F
SRV_RANDOM_MAP = 0x21
SRV_SCHEME_ROUND_TIME = 0x11
SRV_SCHEME_TURN_TIME = 0x12
SRV_SCHEME_VICTORIES = 0x13
SRV_SCHEME_WORM_SELECT = 0x14
SRV_SCHEME_WORMS_HP = 0x15
SRV_SCHEME_WORM_PLACEMENT = 0x1D


WA_HEADER = struct.Struct("<BBHBB")
WA_FRAME_HEADER = struct.Struct("<BBHBI")
WA_PACKET_PREFIX = struct.Struct("<BBH")
WA_LOBBY_REST = struct.Struct("<BB")
WA_GAME_REST = struct.Struct("<BI")

# First end-of-round body in captured channel-2 streams; after this, mirroring must stop.
C2_ENDGAME_SENTINEL = b"\x40\x06\x00"

# OpenWA: engine network end also sends EntityMessage::MachineQuit (0x0D)
# via GameRuntime__BeginNetworkGameEnd @ 0x536270 — see docs/OPENWA.md.

# Post-match return-to-lobby marker (captured after 400600 on rank surrender).
C2_ENDGAME_LOBBY_RETURN_PREFIX = b"\xc0\x0d"

_ENDGAME_FANFARE_PREFIXES = (
    b"\x40\x1e\x02\x02",
    b"\x40\x1e\x01\x02",
    b"\x64\x1e\x02\x02",
    b"\x40\x1f\x02\x02",
    b"\x40\x1f\x01\x02",
    b"\x68\x1f\x01\x02",
    b"\x40\x20\x02\x02",
    b"\x44\x02\x02\x02",
)

# TaskMessageType tags on the wire (msg_expand: type = first_byte + 1000; Ghidra WA.exe).
TASK_MSG_WIN_COMMENTARY = 1020  # issue_next_win_message (wire tag 0x14)
TASK_MSG_SURRENDER = 1043  # surrender_team / process_surrender (wire tag 0x2B)
TASK_MSG_WIRE_TAG_WIN = TASK_MSG_WIN_COMMENTARY - 1000  # 0x14
TASK_MSG_WIRE_TAG_SURRENDER = TASK_MSG_SURRENDER - 1000  # 0x2B
TASK_MSG_COMPRESS_TAG_SURRENDER = TASK_MSG_SURRENDER - 0x3EA  # 0x29, msg_compress index
C2_WRAPPER_400204 = b"\x40\x02\x04"
C2_WRAPPER_400204_SUFFIX = b"\x03\x0c\x1e"

# Channel-2 loading ladder (matches wa_probe / WA 3.8.x behaviour).
WA_LOADING_LAST_INDEX = 0x1A
WA_LOADING_DONE_FRAME = 0x0200001B

PLAYER_SLOT_COUNT = 7
PLAYER_NAME_SIZE = 17
PLAYER_STRUCT_SIZE = 120
# Player list (0x0B) body layout matches giannitedesco/wabs `struct wa_playerlist`
# (include/worms/wa-protocol.h): 6-byte prefix + 7×120-byte slots + 0x2D0 padding +
# 4-byte trailer. The local `network protocol` file lists 1176 bytes for 0x0B;
# that figure disagrees with wabs and truncating to 1176 made WA RST after LOGIN2.
PLAYER_LIST_PADDING_SIZE = 0x2D0
# Custom scheme (0x0D): `network protocol` documents total size 308 for this message.
CUSTOM_SCHEME_BODY_BYTES = 308
CUSTOM_SCHEME_DATA_BYTES = CUSTOM_SCHEME_BODY_BYTES - 6  # word + dword id prefix
SCHEMES_DIR = Path(__file__).resolve().parents[2] / "schemes"


TEAM_NAME_SIZE = 17
TEAM_SOUND_BANK_SIZE = 32
TEAM_FANFARE_SIZE = 30
TEAM_WORM_COUNT = 8
TEAM_STRUCT_SIZE = 3458

DEFAULT_WORM_NAMES = (
    "Worm 1",
    "Worm 2",
    "Worm 3",
    "Worm 4",
    "Worm 5",
    "Worm 6",
    "Worm 7",
    "Worm 8",
)

HOST_PLAYER_PROFILE = bytes.fromhex(
    "5e e1 7e 69 02 02 0e 7c 04 01 02 07 02 01 41 52 "
    "04 03 f4 01 01 0d 04 04 72 f8 0f bb 04 05 20 c8 4b 4a"
)
GUEST_PLAYER_PROFILE = bytes.fromhex(
    "5e e1 7e 69 05 04 03 f4 01 01 07 04 04 72 fb 29 22"
)

SCHEME_IDS: dict[str, int] = {
    "beginner": 1,
    "b": 1,
    "intermediate": 2,
    "i": 2,
    "g": 2,
    "pro": 3,
    "p": 3,
    "artillery": 6,
    "art": 6,
    "classic": 7,
    "cl": 7,
    "armageddon": 8,
    "ag": 8,
    "darkside": 9,
    "retro": 11,
    "strategic": 13,
    "strat": 13,
    "suddensinking": 14,
    "sudden-sinking": 14,
    "tournament": 15,
    "blastzone": 16,
    "blast-zone": 16,
    "fullwormage": 17,
    "thefullwormage": 17,
    # Known custom/community schemes fall back to an official default here.
    "wacl": 2,
    "wxw": 2,
    "shopper": 2,
    "rope": 2,
}


@dataclass(frozen=True, slots=True)
class SchemeLobbyOverrides:
    victories: int | None = None
    worm_placement: int | None = None  # 0 = random/auto, 1 = manual


SCHEME_LOBBY_OVERRIDES: dict[str, SchemeLobbyOverrides] = {
    "rank": SchemeLobbyOverrides(victories=1, worm_placement=0),  # 0x1D value 0 = disabled
    "singleround": SchemeLobbyOverrides(victories=1, worm_placement=0),
    "1round": SchemeLobbyOverrides(victories=1, worm_placement=0),
    "sr": SchemeLobbyOverrides(victories=1, worm_placement=0),
    "intermediate1": SchemeLobbyOverrides(victories=1, worm_placement=0),
}


CUSTOM_SCHEME_WSC: dict[str, str] = {
    "rank": "rank.wsc",
    "aerox": "rank.wsc",
}


def _wsc_scheme_body(data: bytes) -> bytes:
    if len(data) < 5 or data[:4] != b"SCHM":
        raise ValueError("expected WSC file with SCHM header")
    return data[5:].ljust(CUSTOM_SCHEME_DATA_BYTES, b"\x00")[:CUSTOM_SCHEME_DATA_BYTES]


def _custom_scheme_payload_from_wsc(path: Path) -> bytes:
    body = _wsc_scheme_body(path.read_bytes())
    return struct.pack("<Hi", 0, -1) + body


def _resolve_custom_scheme_payload(scheme_key: str) -> bytes | None:
    key = scheme_key.strip().lower()
    embedded = CUSTOM_SCHEME_PAYLOADS.get(key)
    if embedded is not None:
        return embedded
    wsc_name = CUSTOM_SCHEME_WSC.get(key)
    if wsc_name is None:
        return None
    wsc_path = SCHEMES_DIR / wsc_name
    if not wsc_path.is_file():
        LOGGER.warning("Custom scheme %r is configured but missing file: %s", key, wsc_path)
        return None
    try:
        payload = _custom_scheme_payload_from_wsc(wsc_path)
    except OSError as exc:
        LOGGER.warning("Failed to read custom scheme %r from %s: %s", key, wsc_path, exc)
        return None
    except ValueError as exc:
        LOGGER.warning("Invalid WSC for scheme %r (%s): %s", key, wsc_path, exc)
        return None
    scheme = bytearray(payload[6 : 6 + CUSTOM_SCHEME_DATA_BYTES])
    overrides = SCHEME_LOBBY_OVERRIDES.get(key)
    if overrides is not None:
        if overrides.worm_placement is not None and len(scheme) > 0x14:
            scheme[0x14] = overrides.worm_placement
        if overrides.victories is not None and len(scheme) > 0x18:
            scheme[0x18] = overrides.victories
        payload = struct.pack("<Hi", 0, -1) + bytes(scheme)
    LOGGER.info(
        "Loaded custom scheme %r from %s (manual_placement=%s victories=%s version=%s)",
        key,
        wsc_path,
        scheme[0x14] if len(scheme) > 0x14 else "?",
        scheme[0x18] if len(scheme) > 0x18 else "?",
        wsc_path.read_bytes()[4] if wsc_path.stat().st_size >= 5 else "?",
    )
    return payload


_SINGLE_ROUND_SCHEME = bytes.fromhex(
    "0000ffffffff05030500010100000000020214000a190a05030100642d0f0100"
    "000000000000000001010a02000001020101050200010a020001030200010102"
    "020102020001000200010a0200000a0200000a02000000020002020200010102"
    "050101020701020200010a0200000a020000010200000a020000020200010302"
    "0001030200010302000105020001020000010200000102000001010200010102"
    "0001010200010002000200020002000200020002000200020002000200020002"
    "0002000200020000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000"
)

CUSTOM_SCHEME_PAYLOADS: dict[str, bytes] = {
    "eliteleague": bytes.fromhex(
        "0000ffffffff000003030001010000000003031e000a190a0500010164140a01"
        "00000000000000000001000a02000001020101030200000a0200000301000101"
        "02000102020000000200010a0200000a0200000a020000000200010202000101"
        "02050101020701020200000a0200000a020000010200000a0200000202000002"
        "0200000202000002020001020000010200000002000000020000000102000101"
        "0205010102030000020002000200020002000200020002000200020002000200"
        "0200020002000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000"
    ),
}


@dataclass(slots=True)
class SessionStatus:
    bind_host: str
    port: int
    scheme: str
    scheme_id: int
    join_attempts: int
    connected_players: int


@dataclass(slots=True)
class LobbyPlayer:
    player_id: int
    nickname: str
    country: int
    writer: asyncio.StreamWriter | None
    profile: bytes | None = None
    ready: bool = False
    team_slot: int | None = None


@dataclass(slots=True)
class LobbyTeam:
    slot: int
    player_id: int
    color: int
    name: str
    soundbank: str
    fanfare: str
    worm_names: tuple[str, ...]
    raw_payload: bytes | None = None


def _encode_fixed_string(value: str, length: int) -> bytes:
    encoded = value.encode("latin-1", errors="replace")[:length]
    if len(encoded) < length:
        encoded += b"\x00" * (length - len(encoded))
    return encoded


def _decode_c_string(data: bytes) -> str:
    return data.split(b"\x00", 1)[0].decode("latin-1", errors="replace")


def _body_preview(data: bytes, limit: int = 64) -> str:
    if not data:
        return "<empty>"
    preview = data[:limit].hex(" ")
    if len(data) > limit:
        preview += f" ... (+{len(data) - limit} bytes)"
    return preview


def _packet_family(body: bytes) -> str:
    if not body:
        return "<empty>"
    if body == C2_ENDGAME_SENTINEL:
        return "400600"
    if body.startswith(bytes.fromhex("400204")) and len(body) >= 7:
        return f"400204/{body[3]:02x}/{body[4:7].hex()}"
    if body.startswith(bytes.fromhex("401e0102")) and len(body) >= 8:
        return f"401e0102/{body[4:8].hex()}"
    if body.startswith(bytes.fromhex("401e0202")) and len(body) >= 8:
        return f"401e0202/{body[4:8].hex()}"
    if body.startswith(bytes.fromhex("401f0102")) and len(body) >= 8:
        return f"401f0102/{body[4:8].hex()}"
    if body.startswith(bytes.fromhex("401f0202")) and len(body) >= 8:
        return f"401f0202/{body[4:8].hex()}"
    if len(body) >= 4:
        return body[:4].hex()
    return body.hex()


def _slot_from_endgame_family(family: str) -> int | None:
    prefix = family.split("/", 1)[0]
    if len(prefix) != 8:
        return None
    # Multi-team winner inference stays intentionally conservative. We have
    # seen several slot-coded families near game end that refer to eliminations
    # or other endgame state, but only the 0x4020/0x4021 ...1e families have
    # been consistently validated as positive winner-slot signals.
    if prefix[:4] not in {"4020", "4021"}:
        return None
    if prefix[6:8] != "1e":
        return None
    try:
        slot = int(prefix[4:6], 16)
    except ValueError:
        return None
    return slot if slot > 0 else None


def _wire_tag_to_task_message_type(tag: int) -> int:
    return (tag & 0xFF) + 1000


def _surrender_team_indices_in_body(body: bytes) -> list[int]:
    """Candidate surrendered team indices embedded in a channel-2 body (may be 0- or 1-based)."""
    indices: list[int] = []
    for msg_type, payload in parse_c2_400204_wrappers(body):
        if msg_type == TASK_MSG_SURRENDER and payload:
            indices.append(payload[0])
    # Ghidra msg_compress case 0x27..0x2e: 2-byte record [tag][team_byte]; ignore buried tags in bulk.
    if len(body) <= 16:
        for i in range(len(body) - 1):
            tag = body[i]
            if tag in (TASK_MSG_WIRE_TAG_SURRENDER, TASK_MSG_COMPRESS_TAG_SURRENDER):
                indices.append(body[i + 1])
    return indices


def _map_surrender_index_to_team_slot(index: int, valid_slots: set[int]) -> int | None:
    """Map a raw surrender body index to a lobby team slot (handles 0- vs 1-based)."""
    if index in valid_slots:
        return index
    if index + 1 in valid_slots:
        return index + 1
    if index - 1 in valid_slots:
        return index - 1
    return None


def _is_surrender_task_body(body: bytes) -> bool:
    """Channel-2 bodies observed on menu surrender (Intermediate capture)."""
    if len(body) < 4:
        return False
    return body.startswith(
        (
            b"\x40\x1e\x02\x02",
            b"\x40\x1e\x01\x02",
            b"\x64\x1e\x02\x02",
            b"\x44\x02\x02\x02",
        )
    )


def _is_surrender_endgame_400204_body(body: bytes) -> bool:
    """Post-game 400204 ladder from the surrendering client (rank/fast-surrender path).

    Ghidra: ``surrender_team`` delivers type 1043 (wire tag 0x2B); the surrenderer then
    runs the endgame msg_save ladder (400204 tags for fanfare / commentary steps).
    Captures: rank game loser ``s`` sent 6+ consecutive 400204 bodies; winner sent none.
    """
    for msg_type, _payload in parse_c2_400204_wrappers(body):
        if msg_type != TASK_MSG_SURRENDER:
            return True
    return False


def _pack_lobby(command: int, payload: bytes = b"", *, unknown: int = 0, pad: int = 0) -> bytes:
    return WA_HEADER.pack(LOBBY_CHANNEL, unknown, WA_HEADER.size + len(payload), command, pad) + payload


def _pack_chat(message: str) -> bytes:
    return _pack_lobby(SRV_CHAT, message.encode("latin-1", errors="replace") + b"\x00")


def _pack_login_ok() -> bytes:
    # Real WA hosts send a 6-byte payload here rather than an empty packet.
    payload = struct.pack("<HI", 0, 0x01F4)
    return _pack_lobby(SRV_LOGIN_OK, payload)


def _pack_login_error() -> bytes:
    return _pack_lobby(SRV_LOGIN_ERROR)


def _pack_custom_scheme(payload: bytes) -> bytes:
    if len(payload) > CUSTOM_SCHEME_BODY_BYTES:
        raise ValueError(
            f"Custom scheme payload is {len(payload)} bytes; max {CUSTOM_SCHEME_BODY_BYTES} per WormNET doc"
        )
    body = payload.ljust(CUSTOM_SCHEME_BODY_BYTES, b"\x00")
    return _pack_lobby(SRV_CUSTOM_SCHEME, body)


def _pack_team_color(slot: int, color: int) -> bytes:
    return _pack_lobby(SRV_TEAM_COLOR, struct.pack("<HII", 0, slot, color))


def _pack_ready(player_id: int, ready: bool) -> bytes:
    payload = struct.pack("<HII", 0, 1 if ready else 0, player_id)
    return _pack_lobby(SRV_READY, payload)


def _pack_player_left(player_id: int) -> bytes:
    return _pack_lobby(SRV_PLAYER_LEFT, struct.pack("<HI", 0, player_id))


def _pack_team_remove(team: LobbyTeam) -> bytes:
    # Client 0x10 remove packets observed in captures are `u16 pad + team name`
    # followed by opaque bytes. The name is the stable key WA uses in this lobby
    # UI, so send the minimal name-bearing form.
    payload = struct.pack("<H", 0) + _encode_fixed_string(team.name, TEAM_NAME_SIZE)
    return _pack_lobby(SRV_TEAM_REMOVE, payload)


# Last dword of 0x1C: WA 3.8.x captures use 0x1F4 (500); 0x4C was 3.6.x-era. Wrong value → checksum / load crash.
WA_START_GAME_VERSION_DEFAULT = 0x1F4


def _pack_start_game(logic_seed: int, game_version: int = WA_START_GAME_VERSION_DEFAULT) -> bytes:
    payload = struct.pack("<HI4sI", 0, logic_seed, b"GSAW", game_version)
    return _pack_lobby(SRV_START_GAME, payload)


def _pack_game_frame(player_id: int, frame: int, payload: bytes, *, unknown: int = 0) -> bytes:
    return WA_FRAME_HEADER.pack(GAME_CHANNEL, unknown, WA_FRAME_HEADER.size + len(payload), player_id, frame) + payload


def _pack_loading_frame(player_id: int, frame: int) -> bytes:
    payload = struct.pack("<HH", 0x0AC0, (frame - 1) * 4)
    return _pack_game_frame(player_id, frame, payload)




def _pack_scheme_setting(command: int, value: int) -> bytes:
    """Lobby scheme tweak (network protocol: word 0x3E + dword value)."""
    payload = struct.pack("<HI", 0x003E, value)
    return _pack_lobby(command, payload)


def _scheme_lobby_override_packets(scheme_key: str) -> list[bytes]:
    overrides = SCHEME_LOBBY_OVERRIDES.get(scheme_key.strip().lower())
    if overrides is None:
        return []
    packets: list[bytes] = []
    if overrides.victories is not None:
        packets.append(_pack_scheme_setting(SRV_SCHEME_VICTORIES, overrides.victories))
    if overrides.worm_placement is not None:
        packets.append(_pack_scheme_setting(SRV_SCHEME_WORM_PLACEMENT, overrides.worm_placement))
    return packets

def _pack_default_scheme(scheme_id: int) -> bytes:
    payload = struct.pack("<HI", 0, scheme_id)
    return _pack_lobby(SRV_DEFAULT_SCHEME, payload)


def _pack_random_map(seed1: int, seed2: int) -> bytes:
    payload = struct.pack(
        "<HIIIIIIIIIIII",
        0,
        44,
        2,
        seed1,
        seed2,
        1,
        0,
        1,
        79,
        35,
        0,
        15,
        0,
    )
    return _pack_lobby(SRV_RANDOM_MAP, payload)


def _pack_player_slot(
    nickname: str,
    country: int,
    previous_player_id: int,
    *,
    is_host: bool,
    player_id: int = 0,
    profile: bytes | None = None,
) -> bytes:
    slot = bytearray(PLAYER_STRUCT_SIZE)
    slot[0:PLAYER_NAME_SIZE] = _encode_fixed_string(nickname, PLAYER_NAME_SIZE)
    if profile is not None:
        # LOGIN2 carries the same opaque identity/options area that sits between
        # the name and prev pointer in wa_playerlist.player[]. Preserve it so WA
        # can bind remote lobby rows to the correct frontend player object.
        slot[17:108] = profile[:91].ljust(91, b"\x00")
    elif is_host:
        profile = HOST_PLAYER_PROFILE
        slot[17 : 17 + len(profile)] = profile
    else:
        # WA uses more than the nickname to tell players apart. Sending the same
        # guest profile blob for every joiner caused the first client to never show
        # additional players in the lobby; mix in player_id so each seat is unique.
        profile_bytes = bytearray(GUEST_PLAYER_PROFILE)
        if player_id:
            profile_bytes[4] ^= (player_id * 17) & 0xFF
            profile_bytes[8] ^= (player_id * 131) & 0xFF
            profile_bytes[12] ^= (player_id * 97) & 0xFF
        profile = bytes(profile_bytes)
        slot[17 : 17 + len(profile)] = profile
    struct.pack_into("<h", slot, 108, previous_player_id)
    slot[112] = country & 0xFF
    # Real WA hosts send these flag bytes as 1/1 in the initial lobby list.
    slot[116] = 1
    slot[117] = 1
    return bytes(slot)


def _pack_player_list(players: list[LobbyPlayer], *, local_machine_index: int) -> bytes:
    """Pack SRV_PLAYER_LIST (0x0B).

    Ghidra ``FUN_004c0790`` case ``0xb`` sets ``DAT_008779e0`` from ``pre[2]`` (i32).
    That value is the receiving WA client's global roster slot, not a constant 1.
    """
    payload = bytearray()
    payload.extend(struct.pack("<HI", 0, local_machine_index))
    player_slots = {player.player_id: player for player in players}
    previous_player_id = -1
    for slot_id in range(PLAYER_SLOT_COUNT):
        player = player_slots.get(slot_id)
        if player is None:
            payload.extend(b"\x00" * PLAYER_STRUCT_SIZE)
            continue
        payload.extend(
            _pack_player_slot(
                player.nickname,
                player.country,
                previous_player_id,
                is_host=player.player_id == 0,
                player_id=player.player_id,
                profile=player.profile,
            )
        )
        previous_player_id = player.player_id
    payload.extend(b"\x00" * PLAYER_LIST_PADDING_SIZE)
    payload.extend(struct.pack("<HH", len(players), 0))
    return _pack_lobby(SRV_PLAYER_LIST, bytes(payload))


def _roster_previous_player_id(players_by_id: dict[int, LobbyPlayer], new_player_id: int) -> int:
    """Last occupied roster row strictly below ``new_player_id``.

    Must match ``_pack_player_list`` linkage (walk slot indices, skip empties).
    Using ``new_player_id - 1`` is wrong when lower ids are free after a leave.
    """
    prev = -1
    for slot_id in range(new_player_id):
        if slot_id in players_by_id:
            prev = slot_id
    return prev


def _pack_player_join(new_player: LobbyPlayer, previous_player_id: int) -> bytes:
    """SRV_PLAYER_JOIN (0x0E): one 120-byte roster slot (same layout as 0x0B entries).

    WA expects the same `wa_playerlist.player[]` element as in the full list; a
    6-byte list prefix here misaligns the struct and the joiner is ignored.
    """
    body = _pack_player_slot(
        new_player.nickname,
        new_player.country,
        previous_player_id,
        is_host=new_player.player_id == 0,
        player_id=new_player.player_id,
        profile=new_player.profile,
    )
    return _pack_lobby(SRV_PLAYER_JOIN, body)


def _pack_team_list(team: LobbyTeam, *, owner_id: int | None = None) -> bytes:
    payload = bytearray(TEAM_STRUCT_SIZE)
    struct.pack_into("<H", payload, 2, team.slot)
    payload[6] = (owner_id if owner_id is not None else team.player_id) & 0xFF
    payload[7] = team.color & 0xFF
    payload[9 : 9 + TEAM_NAME_SIZE] = _encode_fixed_string(team.name, TEAM_NAME_SIZE)
    payload[26 : 26 + TEAM_SOUND_BANK_SIZE] = _encode_fixed_string(team.soundbank, TEAM_SOUND_BANK_SIZE)
    payload[60 : 60 + TEAM_FANFARE_SIZE] = _encode_fixed_string(team.fanfare, TEAM_FANFARE_SIZE)
    payload[91 : 91 + TEAM_FANFARE_SIZE] = _encode_fixed_string(team.fanfare, TEAM_FANFARE_SIZE)
    payload[125] = 1
    struct.pack_into("<H", payload, 158, min(len(team.worm_names), TEAM_WORM_COUNT))
    worm_offset = 161
    for index in range(TEAM_WORM_COUNT):
        worm_name = team.worm_names[index] if index < len(team.worm_names) else DEFAULT_WORM_NAMES[index]
        start = worm_offset + (index * PLAYER_NAME_SIZE)
        payload[start : start + PLAYER_NAME_SIZE] = _encode_fixed_string(worm_name, PLAYER_NAME_SIZE)
    return _pack_lobby(SRV_TEAM_LIST, bytes(payload))


def _parse_login(body: bytes) -> tuple[str, str, bytes]:
    nickname = _decode_c_string(body[0:17])
    game_name = _decode_c_string(body[17:34])
    version = body[58:61]
    return nickname, game_name, version


def _parse_login2(body: bytes) -> tuple[str, int, bytes]:
    nickname = _decode_c_string(body[0:17])
    country = body[66] if len(body) > 66 else 15
    return nickname, country, body[17:108]


def _parse_chat(body: bytes) -> tuple[str, str, str, str]:
    parts = _decode_c_string(body).split(":", 3)
    while len(parts) < 4:
        parts.append("")
    return parts[0], parts[1], parts[2], parts[3]


def _parse_team_add_payload(body: bytes) -> LobbyTeam:
    # Client 0x1A packets do not line up with the server-side 0x0C layout we use
    # elsewhere. In captures so far the editable team name starts at byte 6, while
    # the old 0x0C-based offsets caused bogus values like slot=1/name='P'.
    #
    # The first u16 in the payload stays at 1 across multiple client-created teams,
    # so it is not the editable team slot. Some captures showed byte 159 matching
    # the client's internal team index, but that is not stable across all setups,
    # so it is only used as a hint and may be overridden when we merge the team
    # into session state.
    slot = body[159] if len(body) > 159 else (struct.unpack_from("<H", body, 2)[0] if len(body) >= 4 else 0)
    player_id = body[2] if len(body) > 2 else 0
    color = body[7] if len(body) > 7 else 0
    name = _decode_c_string(body[6 : 6 + TEAM_NAME_SIZE]) if len(body) >= 6 + TEAM_NAME_SIZE else ""
    if not name:
        name = _decode_c_string(body[9:26]) if len(body) >= 26 else ""
    soundbank = _decode_c_string(body[26:58]) if len(body) >= 58 else ""
    fanfare = _decode_c_string(body[60:90]) if len(body) >= 90 else ""
    worm_names: list[str] = []
    worm_offset = 161
    for index in range(TEAM_WORM_COUNT):
        start = worm_offset + (index * PLAYER_NAME_SIZE)
        if start >= len(body):
            break
        worm_names.append(_decode_c_string(body[start : start + PLAYER_NAME_SIZE]))
    return LobbyTeam(
        slot=slot,
        player_id=player_id,
        color=color,
        name=name,
        soundbank=soundbank,
        fanfare=fanfare,
        worm_names=tuple(worm_names),
        raw_payload=bytes(body),
    )


def _patch_team_add_payload(body: bytes, team: LobbyTeam, *, owner_id: int) -> bytes:
    """Patch the client-format 0x1A body with host-assigned owner/slot.

    0x1A is not the same layout as server 0x0C. The first six bytes behave like
    a small client-side prefix; captures show byte 2 as the only stable owner-ish
    value, while byte 159 is a useful team-slot hint. Owner ids in this packet
    are local to the receiving WA instance: the selector sends itself as 1, and
    the other human appears as 2. Do not patch colour here: the obvious old offset
    overlaps the team name in this packet format.
    """
    patched = bytearray(body)
    if len(patched) > 2:
        patched[2] = owner_id & 0xFF
    if len(patched) > 159:
        patched[159] = team.slot & 0xFF
    return bytes(patched)


def _replace_lobby_body(packet: bytes, body: bytes) -> bytes:
    return packet[: WA_HEADER.size] + body



def _valid_slots_for_winner(candidate_teams: list["LobbyTeam"]) -> set[int]:
    """One lobby slot per human player_id (lowest slot if duplicate roster entries)."""
    by_player: dict[int, int] = {}
    for team in sorted(candidate_teams, key=lambda t: t.slot):
        by_player.setdefault(team.player_id, team.slot)
    return set(by_player.values())


class GameSession:
    def __init__(
        self,
        config: BotConfig,
        scheme: str,
        *,
        session_owner_nickname: str | None = None,
    ) -> None:
        self.config = config
        self.scheme = scheme
        self._session_owner_nickname = (session_owner_nickname or "").strip() or None
        scheme_key = scheme.strip().lower()
        self.custom_scheme_payload = _resolve_custom_scheme_payload(scheme)
        self.scheme_id = -1 if self.custom_scheme_payload is not None else SCHEME_IDS.get(scheme_key, 2)
        self._server: asyncio.base_events.Server | None = None
        self._client_tasks: set[asyncio.Task[None]] = set()
        self._client_writers: set[asyncio.StreamWriter] = set()
        self._join_attempts = 0
        self._game_started = False
        self._game_start_unix: float | None = None
        self._openwa_winner_sidecar_path = sidecar_path_from_config(
            config.openwa_winner_sidecar_path
        )
        self.on_game_started: Callable[[], Awaitable[None]] | None = None
        self.on_game_ended: Callable[[], Awaitable[None]] | None = None
        # Fires as soon as a deterministic winner is inferred from endgame frames.
        # This does NOT mean all clients have left the result screen yet.
        self.on_winner_inferred: Callable[[str], Awaitable[None]] | None = None
        self._c2_stop_relay: bool = False
        self._client_loading_done: set[asyncio.StreamWriter] = set()
        self._host_loading_echoed_index_by_writer: dict[asyncio.StreamWriter, int] = {}
        self._pending_loading_relay: list[tuple[LobbyPlayer, int, bytes, int, asyncio.StreamWriter]] = []
        self._loading_phase_complete: bool = False
        self._host_player = LobbyPlayer(
            player_id=0,
            nickname=config.nickname,
            country=15,
            writer=None,
        )
        self._players_by_writer: dict[asyncio.StreamWriter, LobbyPlayer] = {}
        self._players_by_id: dict[int, LobbyPlayer] = {}
        self._teams_by_slot: dict[int, LobbyTeam] = {}
        self._editable_teams: list[LobbyTeam] = []
        self._map_seed1 = random.getrandbits(32)
        self._map_seed2 = random.getrandbits(32)
        self._logic_seed = random.getrandbits(32)
        self._capture_dir = Path(__file__).resolve().parents[2] / "captures"
        self._capture_path: Path | None = None
        self._capture_sequence = 0
        self._recent_incoming_game_frames: list[tuple[int, bytes, int | None]] = []
        self._human_endgame_sentinels: set[int] = set()
        self._first_endgame_sentinel_slot: int | None = None
        self._first_endgame_sentinel_frame_by_player: dict[int, int] = {}
        self._first_endgame_lobby_return_frame_by_player: dict[int, int] = {}
        self._players_with_endgame_fanfare: set[int] = set()
        self._human_endgame_lobby_return: set[int] = set()
        self._last_low_endgame_frame_by_player: dict[int, int] = {}
        self._last_endgame_relay_frame_to_player: dict[int, int] = {}
        self._gameplay_active: bool = False
        self._endgame_fanfare_source_player_id: int | None = None
        self._winner_team_name: str | None = None
        self._winner_player_nickname: str | None = None
        self._winner_reason: str | None = None
        self._endgame_tracker: EndgameTracker | None = None
        self._endgame_net: EndgameNetState | None = None
        self._endgame_first_sentinel_mono: float | None = None
        self._endgame_first_c00d_mono: float | None = None
        self._endgame_handshake_assist = EndgameHandshakeAssist()
        self._host_mask_task: asyncio.Task[None] | None = None
        self._gamenet_anchor_frame: int = DEFAULT_GAMENET_FRAME
        self._c2_relay_phase: C2RelayPhase = C2RelayPhase.LOADING
        # One lock per WA TCP writer so lobby + game relay coroutines never interleave writes.
        self._writer_send_locks: dict[asyncio.StreamWriter, asyncio.Lock] = {}
        host_team = self._build_default_team(self._host_player)
        self._host_player.team_slot = host_team.slot
        self._teams_by_slot[host_team.slot] = host_team

    async def start(self) -> None:
        if self._server is not None:
            return
        self._start_capture()
        self._server = await asyncio.start_server(
            self._handle_client,
            host=self.config.game_bind_host,
            port=self.config.game_port,
            reuse_address=True,
        )
        sockets = self._server.sockets or []
        LOGGER.info(
            "Game session listening on %s mapSeed=%08x/%08x",
            ", ".join(str(sock.getsockname()) for sock in sockets) or f"{self.config.game_bind_host}:{self.config.game_port}",
            self._map_seed1,
            self._map_seed2,
        )

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

        for writer in list(self._client_writers):
            writer.close()
        for writer in list(self._client_writers):
            with contextlib.suppress(Exception):
                await writer.wait_closed()
        self._client_writers.clear()

        for task in list(self._client_tasks):
            task.cancel()
        for task in list(self._client_tasks):
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task
        self._client_tasks.clear()
        self._players_by_writer.clear()
        self._players_by_id.clear()
        self._teams_by_slot.clear()
        self._editable_teams.clear()
        self._finish_capture("stopped")

    def status(self) -> SessionStatus:
        return SessionStatus(
            bind_host=self.config.game_bind_host,
            port=self.config.game_port,
            scheme=self.scheme,
            scheme_id=self.scheme_id,
            join_attempts=self._join_attempts,
            connected_players=len(self._players_by_id),
        )

    def _sorted_players(self) -> list[LobbyPlayer]:
        return [self._host_player, *sorted(self._players_by_id.values(), key=lambda player: player.player_id)]

    def _sorted_teams(self) -> list[LobbyTeam]:
        return sorted(self._teams_by_slot.values(), key=lambda team: team.slot)

    def _lobby_player_list_packet_for_peer(self, peer_roster_id: int) -> bytes:
        return _pack_player_list(self._sorted_players(), local_machine_index=peer_roster_id)

    def _lobby_team_list_packets_for_peer(self, peer_roster_id: int) -> list[bytes]:
        """One SRV_TEAM_LIST (0x0C) per human team; owner is global roster id (Ghidra 0x1A/0x0C)."""
        del peer_roster_id  # same team row on every client; owner is roster slot not local 1/2
        return [
            _pack_team_list(team, owner_id=team.player_id)
            for team in self._sorted_teams()
            if team.player_id != self._host_player.player_id
        ]

    def _host_lobby_bundle_packets_for_peer(self, peer_roster_id: int) -> list[bytes]:
        """Full lobby snapshot: RBot at roster 0 plus per-peer team owner ids in 0x0C."""
        packets: list[bytes] = [self._lobby_player_list_packet_for_peer(peer_roster_id)]
        if self.custom_scheme_payload is not None:
            packets.append(_pack_custom_scheme(self.custom_scheme_payload))
        else:
            packets.append(_pack_default_scheme(self.scheme_id))
        override_packets = _scheme_lobby_override_packets(self.scheme)
        for pkt in override_packets:
            LOGGER.info(
                "WA lobby scheme override cmd=0x%02x body=%s",
                pkt[4],
                pkt[WA_HEADER.size:].hex(),
            )
        packets.extend(override_packets)
        packets.append(_pack_random_map(self._map_seed1, self._map_seed2))
        packets.extend(self._lobby_team_list_packets_for_peer(peer_roster_id))
        return packets

    def _allocate_player_id(self, nickname: str) -> int | None:
        """Assign roster ids with optional nickname pins, then ``!jost`` owner reservation."""
        owner = self._session_owner_nickname
        nick_cf = nickname.casefold()
        pinned = self.config.roster_pins.get(nick_cf)
        if pinned is not None and pinned not in self._players_by_id:
            return pinned
        if owner and nick_cf == owner.casefold() and 1 not in self._players_by_id:
            return 1
        for player_id in range(1, PLAYER_SLOT_COUNT):
            if (
                player_id == 1
                and owner
                and 1 not in self._players_by_id
                and nick_cf != owner.casefold()
            ):
                continue
            if player_id not in self._players_by_id:
                return player_id
        return None

    def _allocate_team_slot(self) -> int | None:
        for slot in range(PLAYER_SLOT_COUNT):
            if slot not in self._teams_by_slot:
                return slot
        return None

    def _build_default_team(self, player: LobbyPlayer) -> LobbyTeam:
        slot = self._allocate_team_slot()
        if slot is None:
            raise RuntimeError("No free team slots left in lobby")
        team_name = f"{player.nickname[:12]}'s team"
        worm_names = tuple(
            f"{player.nickname[:10]} {index + 1}"[:PLAYER_NAME_SIZE] for index in range(TEAM_WORM_COUNT)
        )
        return LobbyTeam(
            slot=slot,
            player_id=player.player_id,
            color=player.player_id % 8,
            name=team_name,
            soundbank="default",
            fanfare="default",
            worm_names=worm_names if worm_names else DEFAULT_WORM_NAMES,
            raw_payload=None,
        )

    def _start_capture(self) -> None:
        if self._capture_path is not None:
            return
        self._capture_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        safe_scheme = "".join(ch if ch.isalnum() else "-" for ch in self.scheme.strip()) or "default"
        self._capture_path = self._capture_dir / f"{timestamp}-{safe_scheme}.jsonl"
        self._capture_sequence = 0
        self._append_capture(
            {
                "type": "session_started",
                "scheme": self.scheme,
                "scheme_id": self.scheme_id,
                "custom_scheme": self.custom_scheme_payload is not None,
                "bind_host": self.config.game_bind_host,
                "port": self.config.game_port,
                "map_seed1": self._map_seed1,
                "map_seed2": self._map_seed2,
                "logic_seed": self._logic_seed,
                "session_owner": self._session_owner_nickname,
            }
        )
        self._capture_lobby_snapshot("initial")

    def winner_summary(self) -> str | None:
        if self._winner_team_name is None:
            return None
        summary = self._winner_team_name
        if self._winner_player_nickname:
            summary = f"{summary} [player={self._winner_player_nickname}]"
        if self._winner_reason:
            return f"{summary} ({self._winner_reason})"
        return summary

    def _player_nickname_for_team(self, team: LobbyTeam) -> str | None:
        if team.player_id == self._host_player.player_id:
            return self._host_player.nickname
        player = self._players_by_id.get(team.player_id)
        if player is not None:
            return player.nickname
        return None

    def _finish_capture(self, reason: str) -> None:
        if self._capture_path is None:
            return
        self._append_capture({"type": "session_finished", "reason": reason})
        self._capture_path = None

    def _append_capture(self, event: dict[str, object]) -> None:
        if self._capture_path is None:
            return
        self._capture_sequence += 1
        record = {
            "seq": self._capture_sequence,
            "ts": datetime.now(timezone.utc).isoformat(),
            **event,
        }
        with self._capture_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=True) + "\n")

    def _capture_lobby_snapshot(self, label: str) -> None:
        self._append_capture(
            {
                "type": "lobby_snapshot",
                "label": label,
                "players": [
                    {
                        "player_id": player.player_id,
                        "nickname": player.nickname,
                        "country": player.country,
                        "ready": player.ready,
                        "team_slot": player.team_slot,
                        "is_host": player.player_id == self._host_player.player_id,
                    }
                    for player in self._sorted_players()
                ],
                "teams": [
                    {
                        "slot": team.slot,
                        "player_id": team.player_id,
                        "owner_nickname": self._player_nickname_for_team(team),
                        "color": team.color,
                        "name": team.name,
                        "soundbank": team.soundbank,
                        "fanfare": team.fanfare,
                        "worm_names": list(team.worm_names),
                    }
                    for team in self._sorted_teams()
                ],
            }
        )

    def _capture_packet(
        self,
        *,
        direction: str,
        channel: int,
        peer: object | None,
        nickname: str | None,
        command: int,
        body: bytes,
        frame: int | None = None,
        packet: bytes | None = None,
    ) -> None:
        ws_header_hex: str | None = None
        ws_payload_hex: str | None = None
        # Optional: if the body itself looks like a WS_GameNet 4-byte header + payload,
        # store a split to help offline RE alignment.
        if channel == GAME_CHANNEL and len(body) >= 4:
            cmd = (body[0] >> 4) & 0xF
            peer_idx = body[0] & 0xF
            if cmd <= 3 and peer_idx <= 7:
                ws_header_hex = body[:4].hex()
                ws_payload_hex = body[4:].hex()

        self._append_capture(
            {
                "type": "packet",
                "direction": direction,
                "channel": channel,
                "peer": str(peer) if peer is not None else None,
                "nickname": nickname,
                "command": command,
                "frame": frame,
                "body_hex": body.hex(),
                "packet_hex": packet.hex() if packet is not None else None,
                "ws_header_hex": ws_header_hex,
                "ws_payload_hex": ws_payload_hex,
            }
        )

    def _remember_incoming_game_frame(
        self, frame: int, body: bytes, roster_player_id: int | None = None
    ) -> None:
        self._recent_incoming_game_frames.append((frame, bytes(body), roster_player_id))
        # Must cover winner_endgame_incoming_frames (often 32–256): a 64-frame cap drops
        # task-1020/1043 bodies on longer games before we try to decode them.
        buf_cap = max(512, self.config.winner_endgame_incoming_frames + 128)
        if len(self._recent_incoming_game_frames) > buf_cap:
            del self._recent_incoming_game_frames[
                : len(self._recent_incoming_game_frames) - buf_cap
            ]
        if roster_player_id is not None and roster_player_id != self._host_player.player_id:
            if 0 < frame < 0x1000:
                self._last_low_endgame_frame_by_player[roster_player_id] = frame
            self._maybe_note_gameplay_active(frame, body)
            if self._is_endgame_fanfare_body(body) and self._gameplay_active:
                self._players_with_endgame_fanfare.add(roster_player_id)
                if self._endgame_fanfare_source_player_id is None:
                    self._endgame_fanfare_source_player_id = roster_player_id
            if self._endgame_tracker is not None and self._gameplay_active:
                self._endgame_tracker.observe_body(body)
            import time

            if body == C2_ENDGAME_SENTINEL and self._endgame_first_sentinel_mono is None:
                self._endgame_first_sentinel_mono = time.monotonic()
            if body.startswith(C2_ENDGAME_LOBBY_RETURN_PREFIX) and self._endgame_first_c00d_mono is None:
                self._endgame_first_c00d_mono = time.monotonic()
            if roster_player_id is not None:
                if is_gamenet_transport_body(body):
                    self._gamenet_anchor_frame = max(self._gamenet_anchor_frame, frame)
                self._endgame_handshake_assist.observe(
                    roster_player_id, frame, body
                )
            if self._endgame_net is not None:
                phase_changed = self._endgame_net.observe_incoming(roster_player_id, body)
                if phase_changed is not None:
                    LOGGER.info(
                        "WA endgame net phase -> %s (%s)",
                        phase_changed.name,
                        self._endgame_net.status_summary(),
                    )
                    self._append_capture(
                        {
                            "type": "endgame_net_phase",
                            **self._endgame_net.to_capture_dict(),
                        }
                    )
                    self._on_endgame_phase_changed(phase_changed)

    # Next: once put_message→wire layout is known, prefer typed decode on recent frames.
    # RE (game/WA/WA, WA.lst): ``TaskMessageType`` 0x3FC (1020) = ``issue_next_win_message``
    # (win commentary / fanfare step). 0x413 (1043) = ``flush_surrendered_teams`` /
    # ``surrender_team`` deliver path — not menu-only: ``check_for_vital_deaths`` and
    # ``check_for_survival_deaths`` call ``surrender_team`` when allies are dead /
    # survival rules fire. After ``game_is_over``, turn logic runs ``flush_surrendered_teams``
    # then may ``deliver`` 0x3FD and ``issue_next_win_message``. Wire still needs
    # msg_save/msg_compress proof; see Findings.md and scripts/scan_c2_type_tags.py.
    # Winner from task-1020 (0c14) / loser from task-1043 (0c2b) per Ghidra deliver paths.

    def _set_inferred_winner(
        self,
        winner: LobbyTeam,
        *,
        reason: str,
        details: dict[str, object],
    ) -> None:
        first = self._winner_team_name is None
        winner_player_nickname = self._player_nickname_for_team(winner)
        self._winner_team_name = winner.name
        self._winner_player_nickname = winner_player_nickname
        self._winner_reason = reason
        LOGGER.info(
            "WA probable winner inferred: team=%s player=%s slot=%s owner_player_id=%s reason=%s details=%s",
            winner.name,
            winner_player_nickname or "<unknown>",
            winner.slot,
            winner.player_id,
            reason,
            details,
        )
        self._append_capture(
            {
                "type": "winner_inferred",
                "team_name": winner.name,
                "team_slot": winner.slot,
                "player_id": winner.player_id,
                "player_nickname": winner_player_nickname,
                "reason": reason,
                **details,
            }
        )
        if first and self.on_winner_inferred is not None:
            summary = self.winner_summary()
            if summary is not None:
                asyncio.create_task(self.on_winner_inferred(summary))

    def _try_openwa_winner_sidecar(self, candidate_teams: list[LobbyTeam]) -> bool:
        path = self._openwa_winner_sidecar_path
        if path is None:
            return False
        teams_by_slot = {team.slot: team for team in candidate_teams}
        valid_slots = set(teams_by_slot)
        sidecar = read_openwa_winner_sidecar(
            path,
            not_before_unix=self._game_start_unix,
            log_missing=True,
        )
        if sidecar is None:
            return False
        resolved = sidecar.resolve_lobby_slots(valid_slots)
        if resolved is None:
            return False
        winner_slot, loser_slot = resolved
        winner = teams_by_slot.get(winner_slot)
        if winner is None:
            return False
        loser_team = teams_by_slot.get(loser_slot) if loser_slot is not None else None
        LOGGER.info(
            "WA winner from OpenWA arena sidecar: winner_slot=%s loser_slot=%s hud=%s survivors=%s",
            winner_slot,
            loser_slot,
            sidecar.hud_status_code,
            sidecar.survivor_team_idx_1based,
        )
        self._set_inferred_winner(
            winner,
            reason="openwa-arena",
            details={
                "source": "openwa-team-arena",
                "hud_status_code": sidecar.hud_status_code,
                "survivor_team_idx_1based": list(sidecar.survivor_team_idx_1based),
                "winner_slot": winner_slot,
                "loser_slot": loser_slot,
                "loser_team": loser_team.name if loser_team else None,
                "sidecar_path": str(path),
            },
        )
        return True

    def _parse_announced_winner(
        self,
        endgame_window: list[tuple[int, bytes, int | None]],
        candidate_teams: list[LobbyTeam],
    ) -> bool:
        """Decode Ghidra-backed task announcements (types 1020 / 1043) from C2 bodies."""
        teams_by_slot = {team.slot: team for team in candidate_teams}
        valid_slots = _valid_slots_for_winner(candidate_teams)
        bodies = [body for _frame, body, _roster in endgame_window if body]
        result = announced_result_from_bodies(bodies, valid_slots)
        if result is None or result.winner_slot is None:
            return False

        LOGGER.info(
            "WA winner inferred from task stream: winner_slot=%s loser_slot=%s reason=%s",
            result.winner_slot,
            result.loser_slot,
            result.reason,
        )
        winner = teams_by_slot.get(result.winner_slot)
        if winner is None:
            LOGGER.info(
                "WA announced winner slot=%s not in lobby teams=%s details=%s",
                result.winner_slot,
                sorted(valid_slots),
                result.details,
            )
            return False
        loser_team = (
            teams_by_slot.get(result.loser_slot) if result.loser_slot is not None else None
        )
        self._set_inferred_winner(
            winner,
            reason=result.reason,
            details={
                **result.details,
                "winner_slot": result.winner_slot,
                "loser_slot": result.loser_slot,
                "loser_team": loser_team.name if loser_team else None,
            },
        )
        return True

    def _log_endgame_decode_miss(
        self,
        endgame_window: list[tuple[int, bytes, int | None]],
        valid_slots: set[int],
    ) -> None:
        """Log near-miss bytes for RE when strict task decode finds nothing."""
        bodies = [body for _frame, body, _roster in endgame_window if body]
        gap = summarize_wire_re_gap(bodies)
        self._append_capture({"type": "wire_re_gap", **gap})
        win_raw: list[tuple[int, int]] = []
        sur_raw: list[tuple[int, int]] = []
        for _frame, body, _roster in endgame_window[-48:]:
            win_raw.extend(parse_win_announcements(body))
            sur_raw.extend(parse_surrender_announcements(body))
        LOGGER.info(
            "WA endgame decode miss: valid_slots=%s win_hits=%s sur_hits=%s "
            "(strict task-1020/1043 only; no heuristics)",
            sorted(valid_slots),
            win_raw[-5:],
            sur_raw[-5:],
        )

    def _on_endgame_phase_changed(self, phase: EndgamePhase) -> None:
        """Re-decode winner at handshake milestones; record PLEASE WAIT timing."""
        import time

        # GameNet assist only after both peers sent 400600. Do not use ROUND_ENDING:
        # fanfare/turn-end C2 can set that phase mid-match and must stay PASSIVE.
        if phase == EndgamePhase.NETWORK_END_AWAITING_PEERS:
            self._enter_endgame_relay_mode()
            asyncio.create_task(
                self._endgame_handshake_assist.maybe_kick(self, reason=phase.name)
            )

        now = time.monotonic()
        if phase == EndgamePhase.COMPLETE and self._endgame_first_sentinel_mono is not None:
            please_wait_s = round(now - self._endgame_first_sentinel_mono, 2)
            net = self._endgame_net
            self._append_capture(
                {
                    "type": "endgame_handshake_timing",
                    "please_wait_seconds": please_wait_s,
                    "likely_fallback": please_wait_s >= 8.0,
                    "entered_round_ending_without_net_end": (
                        net.entered_round_ending_without_net_end if net else None
                    ),
                }
            )
            if please_wait_s >= 8.0:
                LOGGER.warning(
                    "WA endgame PLEASE WAIT fallback likely (%.1fs sentinel->c00d); %s",
                    please_wait_s,
                    net.status_summary() if net else "endgame_net=off",
                )
        if phase in (
            EndgamePhase.NETWORK_END_AWAITING_PEERS,
            EndgamePhase.COMPLETE,
        ):
            self._infer_winner_from_recent_game_frames()

    def _infer_winner_from_recent_game_frames(self) -> None:
        if self._winner_team_name is not None:
            return

        candidate_teams = [
            team
            for team in self._sorted_teams()
            if team.player_id != self._host_player.player_id and not team.name.endswith("'s team")
        ]
        if len(candidate_teams) < 2:
            return
        valid_slots = _valid_slots_for_winner(candidate_teams)

        # Endgame task announcements (1020/1043) may appear slightly before the first 400600,
        # and packets can be buffered/delayed per-peer. Use a larger minimum window here so
        # we don't miss the decisive frame.
        w = self.config.winner_endgame_incoming_frames
        window = max(w, 256)
        recent_tail = self._recent_incoming_game_frames[-window:]
        recent_hex = [body.hex() for _, body, _ in recent_tail if body and body != C2_ENDGAME_SENTINEL]
        if not recent_hex:
            return

        endgame_window = [
            (frame, body, roster_id)
            for frame, body, roster_id in recent_tail
            if body and body != C2_ENDGAME_SENTINEL
        ]
        if self._parse_announced_winner(endgame_window, candidate_teams):
            return

        if self._endgame_tracker is not None:
            tracked = self._endgame_tracker.announced_result()
            if tracked is not None and tracked.winner_slot is not None:
                teams_by_slot = {team.slot: team for team in candidate_teams}
                winner = teams_by_slot.get(tracked.winner_slot)
                if winner is not None:
                    LOGGER.info(
                        "WA winner inferred from endgame tracker: winner_slot=%s loser_slot=%s reason=%s eliminated=%s",
                        tracked.winner_slot,
                        tracked.loser_slot,
                        tracked.reason,
                        tracked.details.get("eliminated_slots"),
                    )
                    loser_team = (
                        teams_by_slot.get(tracked.loser_slot)
                        if tracked.loser_slot is not None
                        else None
                    )
                    self._set_inferred_winner(
                        winner,
                        reason=tracked.reason,
                        details={
                            **tracked.details,
                            "winner_slot": tracked.winner_slot,
                            "loser_slot": tracked.loser_slot,
                            "loser_team": loser_team.name if loser_team else None,
                        },
                    )
                    return

        if self._try_openwa_winner_sidecar(candidate_teams):
            return

        self._log_endgame_decode_miss(endgame_window, valid_slots)
        LOGGER.info(
            "WA winner not announced on wire (no task-1020/1043) window=%s buffered=%s",
            window,
            len(recent_tail),
        )

    def _send_lock_for(self, writer: asyncio.StreamWriter) -> asyncio.Lock:
        lock = self._writer_send_locks.get(writer)
        if lock is None:
            lock = asyncio.Lock()
            self._writer_send_locks[writer] = lock
        return lock

    async def _send_packets(self, writer: asyncio.StreamWriter, *packets: bytes) -> None:
        async with self._send_lock_for(writer):
            for packet in packets:
                writer.write(packet)
            await writer.drain()

    async def _send_full_state(self, writer: asyncio.StreamWriter) -> None:
        lobby_player = self._players_by_writer.get(writer)
        if lobby_player is None:
            return
        packets = self._host_lobby_bundle_packets_for_peer(lobby_player.player_id)
        peer = writer.get_extra_info("peername")
        for packet in packets:
            channel, _, _, command, _ = WA_HEADER.unpack(packet[: WA_HEADER.size])
            body = packet[WA_HEADER.size :]
            self._capture_packet(
                direction="out",
                channel=channel,
                peer=peer,
                nickname=None,
                command=command,
                body=body,
            )
        await self._send_packets(writer, *packets)

    async def _replay_foreign_team_adds_for_joiner(
        self, joiner: LobbyPlayer, writer: asyncio.StreamWriter
    ) -> None:
        """Re-send other humans' CMD_TEAM_ADD (0x1A) so late joiners match real WA lobby state.

        The LOGIN2 bundle already includes ``SRV_TEAM_LIST`` (0x0C), but WA still tracks which
        teams are "live" in the selector from **0x1A** traffic. Joiners who only see 0x0C miss
        teams another client added before they connected.
        """
        for team in self._sorted_teams():
            if team.player_id in (self._host_player.player_id, joiner.player_id):
                continue
            if team.raw_payload is None:
                continue
            patched_body = _patch_team_add_payload(team.raw_payload, team, owner_id=team.player_id)
            packet = _pack_lobby(CMD_TEAM_ADD, patched_body)
            LOGGER.info(
                "WA replay prior 0x1A to joiner=%s nick=%s from roster_owner=%s slot=%s",
                joiner.player_id,
                joiner.nickname,
                team.player_id,
                team.slot,
            )
            await self._send_lobby_packet(
                writer,
                packet,
                command=CMD_TEAM_ADD,
                body=patched_body,
            )

    async def _broadcast_lobby_state(self, exclude: asyncio.StreamWriter | None = None) -> None:
        for writer in list(self._client_writers):
            if writer is exclude:
                continue
            lobby_player = self._players_by_writer.get(writer)
            if lobby_player is None:
                continue
            packets = self._host_lobby_bundle_packets_for_peer(lobby_player.player_id)
            try:
                await self._send_packets(writer, *packets)
            except Exception as exc:
                LOGGER.warning("Failed to broadcast lobby state: %s", exc)

    async def _notify_player_joined(self, new_player: LobbyPlayer) -> None:
        if new_player.player_id == self._host_player.player_id:
            return
        prev_link = _roster_previous_player_id(self._players_by_id, new_player.player_id)
        packet = _pack_player_join(new_player, prev_link)
        body = packet[WA_HEADER.size :]
        for writer in list(self._client_writers):
            if writer is new_player.writer:
                continue
            try:
                self._capture_packet(
                    direction="out",
                    channel=LOBBY_CHANNEL,
                    peer=writer.get_extra_info("peername"),
                    nickname=new_player.nickname,
                    command=SRV_PLAYER_JOIN,
                    body=body,
                )
                await self._send_packets(writer, packet)
            except Exception as exc:
                LOGGER.warning("Failed to send 0x0E player join to peer: %s", exc)
        LOGGER.info(
            "WA player join notify 0x0E sent for nick=%s player_id=%s to %s other client(s)",
            new_player.nickname,
            new_player.player_id,
            max(0, len(self._client_writers) - 1),
        )

    async def _broadcast_ready(self, player: LobbyPlayer) -> None:
        """Fan out SRV_READY (0x0F) with global roster ``player_id`` to every TCP client."""
        packet = _pack_ready(player.player_id, player.ready)
        body = packet[WA_HEADER.size :]
        for writer in list(self._client_writers):
            try:
                self._capture_packet(
                    direction="out",
                    channel=LOBBY_CHANNEL,
                    peer=writer.get_extra_info("peername"),
                    nickname=player.nickname,
                    command=SRV_READY,
                    body=body,
                )
                await self._send_packets(writer, packet)
            except Exception as exc:
                LOGGER.warning("Failed to broadcast ready state: %s", exc)

    async def _broadcast_ready_snapshot(self) -> None:
        """Send SRV_READY for every roster entry to all clients."""
        for lobby_player in self._sorted_players():
            packet = _pack_ready(lobby_player.player_id, lobby_player.ready)
            body = packet[WA_HEADER.size :]
            for writer in list(self._client_writers):
                try:
                    self._capture_packet(
                        direction="out",
                        channel=LOBBY_CHANNEL,
                        peer=writer.get_extra_info("peername"),
                        nickname=lobby_player.nickname,
                        command=SRV_READY,
                        body=body,
                    )
                    await self._send_packets(writer, packet)
                except Exception as exc:
                    LOGGER.warning("Failed to broadcast ready snapshot: %s", exc)

    async def _broadcast_player_left(self, player: LobbyPlayer) -> None:
        packet = _pack_player_left(player.player_id)
        body = packet[WA_HEADER.size :]
        for writer in list(self._client_writers):
            try:
                self._capture_packet(
                    direction="out",
                    channel=LOBBY_CHANNEL,
                    peer=writer.get_extra_info("peername"),
                    nickname=player.nickname,
                    command=SRV_PLAYER_LEFT,
                    body=body,
                )
                await self._send_packets(writer, packet)
            except Exception as exc:
                LOGGER.warning("Failed to broadcast player-left state: %s", exc)

    async def _broadcast_team_removed(self, team: LobbyTeam) -> None:
        packet = _pack_team_remove(team)
        body = packet[WA_HEADER.size :]
        for writer in list(self._client_writers):
            try:
                self._capture_packet(
                    direction="out",
                    channel=LOBBY_CHANNEL,
                    peer=writer.get_extra_info("peername"),
                    nickname=None,
                    command=SRV_TEAM_REMOVE,
                    body=body,
                )
                await self._send_packets(writer, packet)
            except Exception as exc:
                LOGGER.warning("Failed to broadcast team removal: %s", exc)

    async def _relay_lobby_packet(
        self,
        packet: bytes,
        *,
        command: int,
        body: bytes,
        exclude: asyncio.StreamWriter | None = None,
    ) -> None:
        """Forward an exact lobby packet to peers.

        Team packets are especially sensitive to opaque bytes. Rebuilding them
        with a fresh header can drop the original unknown/pad fields, so preserve
        the client's wire image when RBot is just acting as the TCP hub.
        """
        for peer_writer in list(self._client_writers):
            if peer_writer is exclude:
                continue
            try:
                self._capture_packet(
                    direction="out",
                    channel=LOBBY_CHANNEL,
                    peer=peer_writer.get_extra_info("peername"),
                    nickname=None,
                    command=command,
                    body=body,
                )
                await self._send_packets(peer_writer, packet)
            except Exception as exc:
                LOGGER.warning("Failed to relay lobby packet 0x%02X: %s", command, exc)

    async def _send_lobby_packet(
        self,
        writer: asyncio.StreamWriter,
        packet: bytes,
        *,
        command: int,
        body: bytes,
    ) -> None:
        self._capture_packet(
            direction="out",
            channel=LOBBY_CHANNEL,
            peer=writer.get_extra_info("peername"),
            nickname=None,
            command=command,
            body=body,
        )
        await self._send_packets(writer, packet)

    async def set_team_color(self, team_index: int, color: int) -> LobbyTeam:
        teams = self._editable_teams
        if team_index < 1 or team_index > len(teams):
            raise RuntimeError(f"Team index must be between 1 and {len(teams)}")
        team = teams[team_index - 1]
        team.color = color & 0xFFFFFFFF
        packet = _pack_team_color(team_index - 1, team.color)
        for writer in list(self._client_writers):
            try:
                await self._send_packets(writer, packet)
            except Exception as exc:
                LOGGER.warning("Failed to send team color change: %s", exc)
        return team

    async def _relay_lobby_chat(self, body: bytes, *, exclude: asyncio.StreamWriter) -> None:
        """Forward one client's lobby chat payload to all other connected WA clients."""
        if not body:
            return
        packet = _pack_lobby(SRV_CHAT, body)
        for peer_writer in list(self._client_writers):
            if peer_writer is exclude:
                continue
            try:
                self._capture_packet(
                    direction="out",
                    channel=LOBBY_CHANNEL,
                    peer=peer_writer.get_extra_info("peername"),
                    nickname=None,
                    command=SRV_CHAT,
                    body=body,
                )
                await self._send_packets(peer_writer, packet)
            except Exception as exc:
                LOGGER.warning("Failed to relay lobby chat: %s", exc)

    async def _broadcast_chat(self, text: str, *, type_: str = "SYS", from_nick: str | None = None) -> None:
        sender = from_nick if from_nick is not None else self._host_player.nickname
        payload = f"{type_}:{sender}:ALL:{text}".encode("latin-1", errors="replace") + b"\x00"
        packet = _pack_lobby(SRV_CHAT, payload)
        for writer in list(self._client_writers):
            try:
                self._capture_packet(
                    direction="out",
                    channel=LOBBY_CHANNEL,
                    peer=writer.get_extra_info("peername"),
                    nickname=sender,
                    command=SRV_CHAT,
                    body=payload,
                )
                await self._send_packets(writer, packet)
            except Exception as exc:
                LOGGER.warning("Failed to broadcast chat: %s", exc)

    async def set_host_ready(self, ready: bool = True) -> None:
        self._host_player.ready = ready
        await self._broadcast_ready(self._host_player)

    async def start_game(self) -> bool:
        """Send 0x1C to every WA TCP client. Returns False if already started, nobody connected, or not all readied."""
        if self._game_started:
            return False
        if not self._client_writers:
            LOGGER.warning("Refusing WA start: no TCP clients connected")
            return False
        not_ready = [p for p in self._sorted_players() if p.writer is not None and not p.ready]
        if not_ready:
            LOGGER.warning(
                "Refusing WA start: not all humans ready (need green bulbs): %s",
                [(p.nickname, p.player_id, p.ready) for p in not_ready],
            )
            return False
        self._game_started = True
        self._game_start_unix = datetime.now(timezone.utc).timestamp()
        self._c2_stop_relay = False
        if self._openwa_winner_sidecar_path is not None:
            clear_openwa_winner_sidecar(self._openwa_winner_sidecar_path)
        self._reset_loading_sync_state()
        self._recent_incoming_game_frames.clear()
        self._human_endgame_sentinels.clear()
        self._first_endgame_sentinel_slot = None
        self._first_endgame_sentinel_frame_by_player.clear()
        self._first_endgame_lobby_return_frame_by_player.clear()
        self._players_with_endgame_fanfare.clear()
        self._human_endgame_lobby_return.clear()
        self._last_low_endgame_frame_by_player.clear()
        self._last_endgame_relay_frame_to_player.clear()
        self._gameplay_active = False
        self._endgame_fanfare_source_player_id = None
        self._winner_team_name = None
        self._winner_player_nickname = None
        self._winner_reason = None
        human_slots = {
            team.slot
            for team in self._sorted_teams()
            if team.player_id != self._host_player.player_id
            and not team.name.endswith("'s team")
        }
        self._endgame_tracker = (
            EndgameTracker(human_slots) if len(human_slots) >= 2 else None
        )
        human_player_ids = frozenset(
            player.player_id
            for player in self._sorted_players()
            if player.player_id != self._host_player.player_id and player.writer is not None
        )
        self._endgame_net = (
            EndgameNetState(human_player_ids) if len(human_player_ids) >= 2 else None
        )
        self._endgame_first_sentinel_mono = None
        self._endgame_first_c00d_mono = None
        self._endgame_handshake_assist.reset()
        self._gamenet_anchor_frame = DEFAULT_GAMENET_FRAME
        self._c2_relay_phase = C2RelayPhase.LOADING
        asyncio.create_task(self._stop_host_gamenet_mask_loop())
        ver = self.config.wa_start_game_version
        packets = [_pack_start_game(self._logic_seed, game_version=ver)]
        LOGGER.info(
            "WA start game: logic_seed=0x%08X game_ver=0x%X players=%s clients=%s",
            self._logic_seed,
            ver,
            [player.player_id for player in self._sorted_players()],
            len(self._client_writers),
        )
        self._capture_lobby_snapshot("game_started")
        for writer in list(self._client_writers):
            try:
                self._capture_packet(
                    direction="out",
                    channel=LOBBY_CHANNEL,
                    peer=writer.get_extra_info("peername"),
                    nickname=self._host_player.nickname,
                    command=SRV_START_GAME,
                    body=packets[0][WA_HEADER.size :],
                )
                await self._send_packets(writer, *packets)
            except Exception as exc:
                LOGGER.warning("Failed to start game for client: %s", exc)
        if self.on_game_started is not None:
            try:
                await self.on_game_started()
            except Exception as exc:
                LOGGER.warning("Failed game-start callback: %s", exc)
        return True

    async def _finish_started_game(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        self._players_by_writer.clear()
        self._players_by_id.clear()
        self._teams_by_slot.clear()
        self._editable_teams.clear()
        host_team = self._build_default_team(self._host_player)
        self._host_player.ready = False
        self._host_player.team_slot = host_team.slot
        self._teams_by_slot[host_team.slot] = host_team
        self._game_started = False
        self._reset_loading_sync_state()
        self._finish_capture("game_ended")
        if self.on_game_ended is not None:
            try:
                await self.on_game_ended()
            except Exception as exc:
                LOGGER.warning("Failed game-ended callback: %s", exc)

    def _tcp_human_roster_ids_sorted(self) -> list[int]:
        return sorted(
            p.player_id
            for p in self._sorted_players()
            if p.writer is not None and p.player_id != self._host_player.player_id
        )

    def _game_channel_wire_for_relay(
        self,
        sender: LobbyPlayer,
        peer_writer: asyncio.StreamWriter,
    ) -> int:
        """Wire player byte on relayed channel-2 frames, local to the receiving WA client."""
        receiver = self._players_by_writer.get(peer_writer)
        if receiver is None:
            return sender.player_id & 0xFF
        if sender.player_id == receiver.player_id:
            return 1
        humans = self._tcp_human_roster_ids_sorted()
        if len(humans) <= 2:
            # Local C2 wire on each WA: lower roster id sends as 1, higher as 2;
            # the other human is always the opposite wire on the receiving client.
            if receiver.player_id == min(humans):
                return 2
            return 1
        others = [h for h in humans if h != receiver.player_id]
        try:
            return others.index(sender.player_id) + 2
        except ValueError:
            return sender.player_id & 0xFF

    def _team_add_owner_id_for_peer(self, team_owner_global: int, peer_roster_id: int) -> int:
        """Legacy local wire id helper; lobby team owner bytes use global roster ids instead."""
        humans = self._tcp_human_roster_ids_sorted()
        if len(humans) <= 2:
            return 1 if peer_roster_id == team_owner_global else 2
        if team_owner_global == peer_roster_id:
            return 1
        others = [h for h in humans if h != peer_roster_id]
        try:
            return others.index(team_owner_global) + 2
        except ValueError:
            return team_owner_global & 0xFF

    def _reset_loading_sync_state(self) -> None:
        self._client_loading_done.clear()
        self._host_loading_echoed_index_by_writer.clear()
        self._pending_loading_relay.clear()
        self._loading_phase_complete = False
        self._gameplay_active = False

    def _is_loading_c2_frame(self, frame: int) -> bool:
        return 1 <= frame <= WA_LOADING_LAST_INDEX or frame == WA_LOADING_DONE_FRAME

    def _peer_ready_for_loading_tail_relay(self, peer_writer: asyncio.StreamWriter) -> bool:
        """Peer can accept wire copies of another client's 0x1A / loading-done."""
        if peer_writer in self._client_loading_done:
            return True
        return self._host_loading_echoed_index_by_writer.get(peer_writer, 0) >= WA_LOADING_LAST_INDEX

    def _maybe_note_gameplay_active(self, frame: int, body: bytes) -> None:
        """Ignore post-load 400204 sync when tagging endgame fanfare (OpenWA: same bytes as surrender ladder)."""
        if self._gameplay_active or not self._loading_phase_complete:
            return
        if body.startswith(b"\xc0\x0a"):
            self._gameplay_active = True
            return
        if body.startswith(_ENDGAME_FANFARE_PREFIXES) or body.startswith((b"\x50\x02", b"\x64\x1e")):
            self._gameplay_active = True
            return
        if body == C2_ENDGAME_SENTINEL or body.startswith(C2_ENDGAME_LOBBY_RETURN_PREFIX):
            self._gameplay_active = True
            return
        if frame > 0x26 and not body.startswith(C2_WRAPPER_400204):
            self._gameplay_active = True

    def _is_endgame_fanfare_body(self, body: bytes) -> bool:
        """Win celebration / commentary ladder (shared task stream)."""
        if is_endgame_fanfare_c2_body(body):
            return True
        return body.startswith(
            (b"\x50\x02", b"\x74\x02", b"\x48\x02", b"\x6c\x02", b"\x78\x02", b"\x7c\x02", b"\xd4\x02")
        )

    def _is_network_endgame_handshake_body(self, body: bytes) -> bool:
        return body == C2_ENDGAME_SENTINEL or body.startswith(C2_ENDGAME_LOBBY_RETURN_PREFIX)

    def _is_network_endgame_c2_body(self, body: bytes) -> bool:
        return self._is_network_endgame_handshake_body(body) or self._is_endgame_fanfare_body(body)

    def _assign_endgame_relay_frame(self, peer_player_id: int, sender_frame: int) -> int:
        """Map endgame C2 to the peer's next expected frame index.

        Surrenderer can lag many frames behind the winner (OpenWA captures: loser @ 0x20+,
        winner sentinel @ 0x1D). Sequential fill avoids dropped packets; when peers are
        within a few frames, keep the sender frame to avoid index-jump errors.
        """
        if sender_frame >= 0x1000:
            return sender_frame
        last_in = self._last_low_endgame_frame_by_player.get(peer_player_id, 0)
        last_out = self._last_endgame_relay_frame_to_player.get(peer_player_id, 0)
        last = max(last_in, last_out)
        if last <= 0:
            relay_frame = max(sender_frame, 0x1D)
        elif sender_frame <= last + 3:
            relay_frame = max(sender_frame, last + 1)
        else:
            relay_frame = last + 1
        self._last_endgame_relay_frame_to_player[peer_player_id] = relay_frame
        return relay_frame

    def _should_relay_c2_to_peer(self, frame: int, peer_writer: asyncio.StreamWriter) -> bool:
        """Gate C2 relay so faster clients cannot push loading indices ahead on slower peers.

        Only the tail (0x1A then loading-done) is relayed between humans, and only once the
        recipient has finished its own player-0 ladder (or already sent loading-done). Mid-ladder
        relay caused joiner desync; skipping 0x1A made ``s`` print index jump 26 from wormstv.
        """
        if not self._is_loading_c2_frame(frame):
            return self._loading_phase_complete
        if 1 <= frame <= WA_LOADING_LAST_INDEX:
            # Fan slower client's ladder to a peer that already finished loading.
            # Never push mid-ladder frames onto a client still driving its own Rbot echoes.
            return peer_writer in self._client_loading_done
        if frame == WA_LOADING_DONE_FRAME:
            return self._peer_ready_for_loading_tail_relay(peer_writer)
        return False

    def _all_humans_loading_done(self) -> bool:
        human_writers = [
            writer
            for writer in self._client_writers
            if self._players_by_writer.get(writer) is not None
        ]
        return bool(human_writers) and all(writer in self._client_loading_done for writer in human_writers)


    def _expected_human_player_ids(self) -> set[int]:
        return {
            p.player_id
            for p in self._players_by_id.values()
            if p.player_id != self._host_player.player_id and p.writer is not None
        }

    def _should_stop_c2_relay(self, game_frame: int, body: bytes) -> bool:
        """Stop relaying only when it's safe.

        Vanilla P2P continues to exchange endgame traffic after 400600 (e.g. c00d...),
        so stopping relays on the first 400600 can strand a peer in the 10s PLEASE WAIT
        timeout. Keep relaying until clients disconnect.
        """
        if self._endgame_net is not None and not self._endgame_net.should_keep_relaying():
            return True
        return False


    def _start_host_gamenet_mask_loop(self) -> None:
        """Disabled during PASSIVE gameplay — caused invalid-data spam from Rbot."""
        return

    async def _stop_host_gamenet_mask_loop(self) -> None:
        task = self._host_mask_task
        self._host_mask_task = None
        if task is None or task.done():
            return
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task

    async def _host_gamenet_mask_loop(self) -> None:
        """~1 Hz connection-mask gossip while the match is active (OpenWA host peer 0)."""
        try:
            while self._game_started and not self._c2_stop_relay:
                if self._loading_phase_complete and self._client_writers:
                    frame = gamenet_frame_for_host(self._gamenet_anchor_frame)
                    await self._send_host_c2_to_clients(
                        frame,
                        host_mask_gamenet_body(),
                    )
                await asyncio.sleep(1.0)
        except asyncio.CancelledError:
            raise

    async def _burst_host_gamenet_mask(self, *, count: int = 4) -> None:
        """Extra mask packets when real endgame fanfare starts."""
        for i in range(count):
            frame = gamenet_frame_for_host(self._gamenet_anchor_frame) + i
            await self._send_host_c2_to_clients(
                frame,
                host_mask_gamenet_body(),
            )
            await asyncio.sleep(0.05)

    async def _send_host_c2_to_clients(
        self,
        frame: int,
        payload: bytes,
        *,
        unknown: int = 0,
        only_writers: Iterable[asyncio.StreamWriter] | None = None,
    ) -> None:
        """Send channel-2 as virtual WA host (wire player id 0) to TCP clients."""
        packet = _pack_game_frame(0, frame, payload, unknown=unknown)
        targets = list(only_writers) if only_writers is not None else list(self._client_writers)
        for writer in targets:
            try:
                self._capture_packet(
                    direction="out",
                    channel=GAME_CHANNEL,
                    peer=writer.get_extra_info("peername"),
                    nickname=self._host_player.nickname,
                    command=0,
                    frame=frame,
                    body=payload,
                )
                await self._send_packets(writer, packet)
            except Exception as exc:
                LOGGER.warning("Failed to send host C2 frame: %s", exc)

    async def _echo_host_loading_sync(
        self,
        game_frame: int,
        body: bytes,
        *,
        sender_writer: asyncio.StreamWriter | None = None,
        unknown: int = 0,
    ) -> None:
        """Mimic player=0 loading ladder + magic echo for the sending client only.

        Each WA client drives its own host loading ladder; broadcasting the fastest
        client's progress (or another client's loading-done magic) desyncs slower peers.
        """
        if self._loading_phase_complete:
            if self._is_loading_c2_frame(game_frame):
                return
            # After loading is complete, avoid injecting any host (wire=0) mirror traffic.
            # Vanilla P2P does not include this extra stream, and it appears to interfere
            # with the NetSession end-of-round handshake (10s PLEASE WAIT fallback).
            return

        if sender_writer is None:
            return

        if sender_writer in self._client_loading_done:
            return

        if 1 <= game_frame <= WA_LOADING_LAST_INDEX:
            echoed = self._host_loading_echoed_index_by_writer.get(sender_writer, 0)
            if game_frame <= echoed:
                return
            for idx in range(echoed + 1, game_frame + 1):
                host_body = struct.pack("<HH", 0x0AC0, (idx - 1) * 4)
                LOGGER.info(
                    "WA host loading echo idx=0x%02X to nick=%s",
                    idx,
                    self._players_by_writer.get(sender_writer, LobbyPlayer(0, "?", 0, None)).nickname,
                )
                await self._send_host_c2_to_clients(
                    idx,
                    host_body,
                    unknown=unknown,
                    only_writers=[sender_writer],
                )
            self._host_loading_echoed_index_by_writer[sender_writer] = game_frame
            if game_frame >= WA_LOADING_LAST_INDEX:
                await self._flush_pending_loading_relay(sender_writer)
            return

        if game_frame == WA_LOADING_DONE_FRAME:
            LOGGER.info(
                "WA host loading-done magic echo body=%s to nick=%s",
                _body_preview(body),
                self._players_by_writer.get(sender_writer, LobbyPlayer(0, "?", 0, None)).nickname,
            )
            await self._send_host_c2_to_clients(
                WA_LOADING_DONE_FRAME,
                body,
                unknown=unknown,
                only_writers=[sender_writer],
            )
            self._client_loading_done.add(sender_writer)
            await self._flush_pending_loading_relay(sender_writer)
            if self._all_humans_loading_done():
                self._loading_phase_complete = True
                self._c2_relay_phase = C2RelayPhase.PASSIVE
                LOGGER.info(
                    "WA loading phase complete; C2 relay -> PASSIVE (peer echo only)"
                )
                self._gameplay_active = False
            return

    async def _flush_pending_loading_relay(self, peer_writer: asyncio.StreamWriter) -> None:
        """Deliver queued peer 0x1A / loading-done once this client finished the ladder."""
        if not self._peer_ready_for_loading_tail_relay(peer_writer):
            return
        pending = [
            item
            for item in self._pending_loading_relay
            if item[4] is peer_writer
        ]
        if not pending:
            return
        self._pending_loading_relay = [
            item
            for item in self._pending_loading_relay
            if item[4] is not peer_writer
        ]
        pending.sort(key=lambda item: (item[0].player_id, item[1]))
        for sender, frame, payload, unknown, _target in pending:
            wire = self._game_channel_wire_for_relay(sender, peer_writer) & 0xFF
            packet = _pack_game_frame(wire, frame, payload, unknown=unknown)
            LOGGER.info(
                "WA deferred loading relay from nick=%s to nick=%s frame=0x%08X",
                sender.nickname,
                self._players_by_writer.get(peer_writer, LobbyPlayer(0, "?", 0, None)).nickname,
                frame,
            )
            try:
                self._capture_packet(
                    direction="out",
                    channel=GAME_CHANNEL,
                    peer=peer_writer.get_extra_info("peername"),
                    nickname=sender.nickname,
                    command=wire,
                    frame=frame,
                    body=payload,
                )
                await self._send_packets(peer_writer, packet)
            except Exception as exc:
                LOGGER.warning("Failed deferred loading relay: %s", exc)

    async def _relay_synthetic_endgame_sentinel(self, sender: LobbyPlayer, frame: int) -> None:
        """401e/641e surrender path sometimes omits 400600; unblock the waiting peer."""
        if sender.player_id in self._human_endgame_sentinels:
            return
        self._human_endgame_sentinels.add(sender.player_id)
        LOGGER.info(
            "WA synthesizing endgame sentinel for nick=%s roster=%s frame=0x%08X "
            "(401e surrender path did not emit 400600)",
            sender.nickname,
            sender.player_id,
            frame,
        )
        self._append_capture(
            {
                "type": "synthetic_endgame_sentinel",
                "player_id": sender.player_id,
                "player_nickname": sender.nickname,
                "frame": frame,
            }
        )
        for peer_writer in self._client_writers:
            if peer_writer is sender.writer:
                continue
            receiver = self._players_by_writer.get(peer_writer)
            if receiver is None or receiver.player_id == self._host_player.player_id:
                continue
            peer_frame = self._assign_endgame_relay_frame(receiver.player_id, frame)
            wire = self._game_channel_wire_for_relay(sender, peer_writer) & 0xFF
            packet = _pack_game_frame(wire, peer_frame, C2_ENDGAME_SENTINEL)
            try:
                self._capture_packet(
                    direction="out",
                    channel=GAME_CHANNEL,
                    peer=peer_writer.get_extra_info("peername"),
                    nickname=sender.nickname,
                    command=wire,
                    frame=peer_frame,
                    body=C2_ENDGAME_SENTINEL,
                )
                await self._send_packets(peer_writer, packet)
            except Exception as exc:
                LOGGER.warning("Failed synthetic endgame sentinel relay: %s", exc)

    async def _maybe_synthesize_missing_endgame_sentinels(self) -> None:
        """Disabled — synthetic 400600 desyncs net_end when winner still in fanfare."""
        return

    async def _maybe_inject_endgame_lobby_return(
        self,
        sender: LobbyPlayer,
        frame: int,
        body: bytes,
    ) -> None:
        # Disabled: injecting extra c00d... traffic can interfere with WA's
        # NetSession end handshake. Vanilla P2P already delivers the required
        # endgame messages by relaying as-is.
        return

    def _enter_endgame_relay_mode(self) -> None:
        if self._c2_relay_phase == C2RelayPhase.ENDGAME:
            return
        self._c2_relay_phase = C2RelayPhase.ENDGAME
        LOGGER.info("WA C2 relay phase -> ENDGAME (host assist for net-end)")

    async def _gamenet_host_fanout(
        self,
        sender: LobbyPlayer,
        frame: int,
        payload: bytes,
        *,
        exclude: asyncio.StreamWriter,
    ) -> None:
        """OpenWA star topology: host (wire 0) relays each client GameNet packet to peers."""
        if not is_gamenet_transport_body(payload):
            return
        targets = [w for w in self._client_writers if w is not exclude]
        if not targets:
            return
        await self._send_host_c2_to_clients(frame, payload, only_writers=targets)
        LOGGER.info(
            "WA GameNet host fan-out from nick=%s frame=0x%08X len=%s peers=%s",
            sender.nickname,
            frame,
            len(payload),
            len(targets),
        )

    def _use_gamenet_host_fanout(self) -> bool:
        """Host wire-0 GameNet fan-out is for load only; after that it causes invalid-data spam."""
        return not self._loading_phase_complete

    async def _endgame_gamenet_kick(self, *, reason: str) -> None:
        """Net-end: do not inject host wire-0 traffic (index jump / invalid data from Rbot)."""
        net = self._endgame_net
        if net is None or not net.all_sent_400600:
            self._endgame_handshake_assist._kick_started = False
            LOGGER.debug(
                "WA net-end GameNet kick skipped (%s): both 400600 not seen yet",
                reason,
            )
            return
        self._enter_endgame_relay_mode()
        self._append_capture(
            {
                "type": "net_end_handshake_status",
                "implemented": False,
                "reason": reason,
                "note": "no host inject at net-end; peer relay only (mask burst caused invalid data)",
            }
        )
        LOGGER.info(
            "WA net-end at 400600 (%s); host GameNet assist off (peer C2 relay only)",
            reason,
        )

    async def _relay_gamenet_burst(self) -> None:
        """Re-send recent channel-2 frames peer-to-peer (no host wire-0 at endgame)."""
        humans = sorted(self._expected_human_player_ids())
        if len(humans) < 2:
            return
        by_id = {
            p.player_id: p
            for p in self._sorted_players()
            if p.player_id in humans and p.writer is not None
        }
        for src_id in humans:
            sender = by_id.get(src_id)
            if sender is None or sender.writer is None:
                continue
            recent = self._endgame_handshake_assist._recent_by_player.get(src_id, ())
            for frame, body in list(recent)[-6:]:
                await self._relay_c2_to_peers(
                    sender,
                    frame,
                    body,
                    exclude=sender.writer,
                    unknown=0,
                )

    async def _relay_c2_to_peers(
        self,
        sender: LobbyPlayer,
        frame: int,
        payload: bytes,
        *,
        exclude: asyncio.StreamWriter,
        unknown: int = 0,
    ) -> None:
        """Fan out channel-2 to other WA TCP clients (per-peer local wire id)."""
        relay_targets = [
            peer_writer
            for peer_writer in self._client_writers
            if peer_writer is not exclude and self._should_relay_c2_to_peer(frame, peer_writer)
        ]
        if self._is_loading_c2_frame(frame):
            for peer_writer in self._client_writers:
                if peer_writer is exclude:
                    continue
                if peer_writer in relay_targets:
                    continue
                self._pending_loading_relay.append((sender, frame, payload, unknown, peer_writer))
        deferred = 0
        if self._is_loading_c2_frame(frame):
            deferred = max(0, len(self._client_writers) - 1 - len(relay_targets))
        LOGGER.info(
            "WA relay C2 from nick=%s roster=%s unk=0x%02X frame=0x%08X body=%s to_peers=%s deferred=%s",
            sender.nickname,
            sender.player_id,
            unknown & 0xFF,
            frame,
            _body_preview(payload),
            len(relay_targets),
            deferred,
        )
        for peer_writer in relay_targets:
            receiver = self._players_by_writer.get(peer_writer)
            relay_frame = frame
            if receiver is not None and self._is_network_endgame_c2_body(payload):
                # Endgame traffic is highly order-sensitive; keep the sender frame index
                # for all endgame-class bodies (including fanfare ladder) to avoid index-jump.
                relay_frame = frame
            wire = self._game_channel_wire_for_relay(sender, peer_writer) & 0xFF
            packet = _pack_game_frame(wire, relay_frame, payload, unknown=unknown)
            try:
                self._capture_packet(
                    direction="out",
                    channel=GAME_CHANNEL,
                    peer=peer_writer.get_extra_info("peername"),
                    nickname=sender.nickname,
                    command=wire,
                    frame=relay_frame,
                    body=payload,
                )
                await self._send_packets(peer_writer, packet)
                if self._is_loading_c2_frame(frame):
                    self._pending_loading_relay = [
                        item
                        for item in self._pending_loading_relay
                        if not (
                            item[0].player_id == sender.player_id
                            and item[1] == frame
                            and item[4] is peer_writer
                        )
                    ]
            except Exception as exc:
                LOGGER.warning("Failed to relay C2 frame: %s", exc)

    def _remove_player(self, writer: asyncio.StreamWriter) -> tuple[LobbyPlayer, list[LobbyTeam]] | None:
        player = self._players_by_writer.pop(writer, None)
        if player is None:
            return None
        self._players_by_id.pop(player.player_id, None)
        removed_teams = [team for team in self._sorted_teams() if team.player_id == player.player_id]
        for team in removed_teams:
            self._teams_by_slot.pop(team.slot, None)
        self._editable_teams = [team for team in self._editable_teams if team.player_id != player.player_id]
        return player, removed_teams

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.current_task()
        if task is not None:
            self._client_tasks.add(task)
        self._client_writers.add(writer)

        peer = writer.get_extra_info("peername")
        player_nick = "<unknown>"
        country = 15
        player: LobbyPlayer | None = None

        try:
            while True:
                prefix = await reader.readexactly(WA_PACKET_PREFIX.size)
                channel, unknown, packet_len = WA_PACKET_PREFIX.unpack(prefix)
                command = 0
                pad = 0
                game_frame = 0

                if channel == LOBBY_CHANNEL:
                    if packet_len < WA_HEADER.size:
                        raise RuntimeError(
                            f"Invalid WA lobby packet length: {packet_len} "
                            f"prefix={prefix.hex(' ')} channel=0x{channel:02X} unknown=0x{unknown:02X}"
                        )
                    header_rest = await reader.readexactly(WA_LOBBY_REST.size)
                    command, pad = WA_LOBBY_REST.unpack(header_rest)
                    body = await reader.readexactly(packet_len - WA_HEADER.size)
                    raw_lobby_packet = prefix + header_rest + body
                elif channel == GAME_CHANNEL:
                    if packet_len < WA_FRAME_HEADER.size:
                        raise RuntimeError(
                            f"Invalid WA game packet length: {packet_len} "
                            f"prefix={prefix.hex(' ')} channel=0x{channel:02X} unknown=0x{unknown:02X}"
                        )
                    header_rest = await reader.readexactly(WA_GAME_REST.size)
                    command, game_frame = WA_GAME_REST.unpack(header_rest)
                    body = await reader.readexactly(packet_len - WA_FRAME_HEADER.size)
                    raw_game_packet = prefix + header_rest + body
                else:
                    if packet_len < WA_PACKET_PREFIX.size:
                        raise RuntimeError(
                            f"Invalid WA packet length: {packet_len} "
                            f"prefix={prefix.hex(' ')} channel=0x{channel:02X} unknown=0x{unknown:02X}"
                        )
                    # Non-lobby/non-game channels have shown up in captures as short
                    # control packets (for example channel 0x05 with total length 4).
                    # We do not know their inner structure yet, so do not try to
                    # parse a lobby-style command header here; just preserve the raw
                    # payload and keep the session alive.
                    body = await reader.readexactly(packet_len - WA_PACKET_PREFIX.size)
                    raw_game_packet = None
                    raw_lobby_packet = None

                if channel == LOBBY_CHANNEL:
                    if command == CMD_CHAT:
                        msg_type, from_nick, to_nick, text = _parse_chat(body)
                        LOGGER.info(
                            "WA chat from %s nick=%s type=%s to=%s text=%r",
                            peer,
                            from_nick or player_nick,
                            msg_type,
                            to_nick,
                            text,
                        )
                        self._capture_packet(
                            direction="in",
                            channel=LOBBY_CHANNEL,
                            peer=peer,
                            nickname=from_nick or player_nick,
                            command=CMD_CHAT,
                            body=body,
                            packet=raw_lobby_packet,
                        )
                        lowered = text.strip().lower()
                        if lowered == "!ready":
                            await self.set_host_ready(True)
                            await self._broadcast_chat("Rbot is ready.")
                        elif lowered == "!start":
                            if not await self.start_game():
                                await self._broadcast_chat(
                                    "Start ignored: everyone must show ready (green) before !start."
                                )
                        elif lowered.startswith("!color "):
                            parts = lowered.split()
                            if len(parts) == 3:
                                try:
                                    team_index = int(parts[1])
                                    color_index = int(parts[2])
                                except ValueError:
                                    await self._broadcast_chat("Usage: !color <team> <color 1-6>")
                                else:
                                    if color_index < 1 or color_index > 6:
                                        await self._broadcast_chat("Color must be between 1 and 6.")
                                    else:
                                        try:
                                            team = await self.set_team_color(team_index, color_index - 1)
                                        except Exception as exc:
                                            await self._broadcast_chat(f"Color failed: {exc}")
                                        else:
                                            await self._broadcast_chat(
                                                f"Set team {team_index} color to {color_index}."
                                            )
                            else:
                                await self._broadcast_chat("Usage: !color <team> <color 1-6>")
                        else:
                            # RBot is the TCP host: humans do not talk to each other directly.
                            # Relay normal lobby chat (GLB:...) to every other WA client.
                            await self._relay_lobby_chat(body, exclude=writer)
                    elif command == CMD_LOGIN:
                        # Same join **shape** as real WA: client 0x04 → host 0x08 → client 0x05 → lobby dump.
                        # `_pack_login_ok` matches captures (6-byte body, u32 0x1F4). Listed games on real WA
                        # reject a wrong LOGIN game-id string (0x27 after 0x2E); RBot does **not** enforce that
                        # so probes/bots can join without IRC listing context—tighten here only if you need
                        # WormNET-faithful rejects (e.g. match an advertised id from config).
                        self._join_attempts += 1
                        player_nick, game_name, version = _parse_login(body)
                        LOGGER.info(
                            "WA join step1 from %s nick=%s game=%s version=%s",
                            peer,
                            player_nick,
                            game_name or "<ip-game>",
                            version.hex(" "),
                        )
                        await self._send_packets(writer, _pack_login_ok())
                    elif command == CMD_LOGIN2:
                        player_nick, country, profile = _parse_login2(body)
                        player = self._players_by_writer.get(writer)
                        login2_is_new_human = False
                        if player is None:
                            login2_is_new_human = True
                            player_id = self._allocate_player_id(player_nick)
                            if player_id is None:
                                LOGGER.warning("Rejecting WA join from %s nick=%s: lobby full", peer, player_nick)
                                await self._send_packets(writer, _pack_login_error())
                                return
                            player = LobbyPlayer(
                                player_id=player_id,
                                nickname=player_nick,
                                country=country,
                                writer=writer,
                                profile=profile,
                            )
                            team = self._build_default_team(player)
                            player.team_slot = team.slot
                            self._players_by_writer[writer] = player
                            self._players_by_id[player.player_id] = player
                            self._teams_by_slot[team.slot] = team
                            # Real WA clears everyone else's ready when a new human joins (joiner starts unready).
                            for existing in self._sorted_players():
                                if existing.player_id in (
                                    self._host_player.player_id,
                                    player.player_id,
                                ):
                                    continue
                                existing.ready = False
                        else:
                            player.nickname = player_nick
                            player.country = country
                            player.profile = profile
                        LOGGER.info(
                            "WA join step2 from %s nick=%s player=%s country=%s scheme=%s(%s) session_owner=%s",
                            peer,
                            player_nick,
                            player.player_id,
                            country,
                            self.scheme,
                            self.scheme_id,
                            self._session_owner_nickname or "<none>",
                        )
                        await self._send_full_state(writer)
                        if login2_is_new_human:
                            await self._replay_foreign_team_adds_for_joiner(player, writer)
                        await self._notify_player_joined(player)
                        await self._broadcast_lobby_state(exclude=writer)
                        await self._broadcast_ready_snapshot()
                    elif command == CMD_READY:
                        ready = len(body) >= 10 and struct.unpack_from("<I", body, 2)[0] != 0
                        packet_player_id = struct.unpack_from("<I", body, 6)[0] if len(body) >= 10 else 0
                        player_id = packet_player_id
                        player = self._players_by_writer.get(writer)
                        if player is not None:
                            # Later joiners still send self as local id 1 in ready
                            # packets. After we echo global id 2, WA no longer
                            # flips its outgoing boolean when that user clicks the
                            # ready bulb again, so repeated True means "toggle me".
                            if ready and player.ready and packet_player_id != player.player_id:
                                ready = False
                            player.ready = ready
                            player_id = player.player_id
                        LOGGER.info(
                            "WA ready from %s nick=%s ready=%s player=%s body=%s",
                            peer,
                            player_nick,
                            ready,
                            player_id,
                            _body_preview(body),
                        )
                        self._capture_packet(
                            direction="in",
                            channel=LOBBY_CHANNEL,
                            peer=peer,
                            nickname=player_nick,
                            command=CMD_READY,
                            body=body,
                        )
                        if player is not None:
                            await self._broadcast_ready(player)
                        else:
                            await self._send_packets(writer, _pack_ready(player_id, ready))
                    elif command == CMD_TEAM_ADD:
                        player = self._players_by_writer.get(writer)
                        team = _parse_team_add_payload(body)
                        if player is not None:
                            # The most reliable owner signal is the socket that sent the
                            # editable team packet, not the ambiguous player byte inside
                            # the payload.
                            team.player_id = player.player_id
                        existing_by_name = next(
                            (
                                existing
                                for existing in self._editable_teams
                                if existing.player_id == team.player_id and existing.name == team.name
                            ),
                            None,
                        )
                        if existing_by_name is not None:
                            team.slot = existing_by_name.slot
                            team.color = existing_by_name.color
                        else:
                            # In normal play a player usually owns one team. Replace
                            # that player's generated default team slot with the first
                            # real custom team they submit. If they submit additional
                            # teams (our single-player tests do this), keep allocating
                            # new synthetic slots so distinct teams are preserved.
                            replaced_default_slot: int | None = None
                            if player is not None and player.team_slot is not None:
                                current_team = self._teams_by_slot.get(player.team_slot)
                                default_team_name = f"{player.nickname[:12]}'s team"
                                if current_team is not None and current_team.name == default_team_name:
                                    replaced_default_slot = current_team.slot

                            if replaced_default_slot is not None:
                                team.slot = replaced_default_slot
                            else:
                                existing_by_slot = self._teams_by_slot.get(team.slot)
                                if team.slot < 0 or (
                                    existing_by_slot is not None
                                    and existing_by_slot.name != team.name
                                ):
                                    allocated_slot = self._allocate_team_slot()
                                    if allocated_slot is not None:
                                        team.slot = allocated_slot
                            # Real WA hosts allocate active team colours globally in
                            # selection order: first active team gets colour 0, next
                            # different player's active team gets colour 1, etc.
                            team.color = len(self._editable_teams) % 8
                        if player is not None and player.team_slot is None:
                            player.team_slot = team.slot
                        self._teams_by_slot[team.slot] = team
                        replaced = False
                        for index, existing in enumerate(self._editable_teams):
                            if existing.slot == team.slot:
                                self._editable_teams[index] = team
                                replaced = True
                                break
                        if not replaced:
                            self._editable_teams.append(team)
                        LOGGER.info(
                            "WA team add from %s nick=%s slot=%s owner_player=%s owner_nick=%s len=%s body=%s",
                            peer,
                            player_nick,
                            team.slot,
                            team.player_id,
                            self._player_nickname_for_team(team) or "<unknown>",
                            packet_len,
                            _body_preview(body),
                        )
                        self._capture_packet(
                            direction="in",
                            channel=LOBBY_CHANNEL,
                            peer=peer,
                            nickname=player_nick,
                            command=CMD_TEAM_ADD,
                            body=body,
                        )
                        self._capture_lobby_snapshot("team_add")
                        # The selector waits for a host echo before leaving
                        # "loading", but echoing a rewritten copy back to that
                        # same client trips WA's duplicate-team guard. Other WA
                        # instances use local owner ids in 0x1A: self is 1 and
                        # the remote human is 2, regardless of RBot's global id.
                        await self._send_lobby_packet(
                            writer,
                            raw_lobby_packet,
                            command=CMD_TEAM_ADD,
                            body=body,
                        )
                        for peer_writer in list(self._client_writers):
                            if peer_writer is writer:
                                continue
                            peer_player = self._players_by_writer.get(peer_writer)
                            if peer_player is None:
                                continue
                            patched_body = _patch_team_add_payload(body, team, owner_id=team.player_id)
                            patched_packet = _replace_lobby_body(raw_lobby_packet, patched_body)
                            await self._send_lobby_packet(
                                peer_writer,
                                patched_packet,
                                command=CMD_TEAM_ADD,
                                body=patched_body,
                            )
                    elif command == CMD_TEAM_REMOVE:
                        LOGGER.info(
                            "WA team remove from %s nick=%s len=%s body=%s",
                            peer,
                            player_nick,
                            packet_len,
                            _body_preview(body),
                        )
                        self._capture_packet(
                            direction="in",
                            channel=LOBBY_CHANNEL,
                            peer=peer,
                            nickname=player_nick,
                            command=CMD_TEAM_REMOVE,
                            body=body,
                        )
                        await self._relay_lobby_packet(
                            raw_lobby_packet,
                            command=CMD_TEAM_REMOVE,
                            body=body,
                        )
                    elif command in {CMD_TEAM_COLOR, CMD_TEAM_HANDICAP, CMD_TEAM_WORMS}:
                        change_name = {
                            CMD_TEAM_COLOR: "color",
                            CMD_TEAM_HANDICAP: "handicap",
                            CMD_TEAM_WORMS: "worms",
                        }[command]
                        LOGGER.info(
                            "WA team %s change from %s nick=%s len=%s body=%s",
                            change_name,
                            peer,
                            player_nick,
                            packet_len,
                            _body_preview(body),
                        )
                        self._capture_packet(
                            direction="in",
                            channel=LOBBY_CHANNEL,
                            peer=peer,
                            nickname=player_nick,
                            command=command,
                            body=body,
                        )
                        await self._relay_lobby_packet(
                            raw_lobby_packet,
                            command=command,
                            body=body,
                        )
                    else:
                        LOGGER.info(
                            "WA lobby packet from %s cmd=0x%02X len=%s nick=%s body=%s",
                            peer,
                            command,
                            packet_len,
                            player_nick,
                            _body_preview(body),
                        )
                        self._capture_packet(
                            direction="in",
                            channel=LOBBY_CHANNEL,
                            peer=peer,
                            nickname=player_nick,
                            command=command,
                            body=body,
                        )
                elif channel == GAME_CHANNEL:
                    LOGGER.info(
                        "WA game frame from %s nick=%s player=%s frame=0x%08X len=%s body=%s",
                        peer,
                        player_nick,
                        command,
                        game_frame,
                        packet_len,
                        _body_preview(body),
                    )
                    self._capture_packet(
                        direction="in",
                        channel=GAME_CHANNEL,
                        peer=peer,
                        nickname=player_nick,
                        command=command,
                        frame=game_frame,
                        body=body,
                        packet=raw_game_packet,
                    )
                    sender_player = self._players_by_writer.get(writer)
                    if sender_player is not None and sender_player.player_id != self._host_player.player_id:
                        self._remember_incoming_game_frame(
                            game_frame, body, sender_player.player_id
                        )
                        if body.startswith(C2_ENDGAME_LOBBY_RETURN_PREFIX):
                            self._first_endgame_lobby_return_frame_by_player.setdefault(
                                sender_player.player_id, game_frame
                            )
                        endgame_sentinel = body == C2_ENDGAME_SENTINEL
                        if endgame_sentinel:
                            self._human_endgame_sentinels.add(sender_player.player_id)
                            self._first_endgame_sentinel_frame_by_player.setdefault(
                                sender_player.player_id, game_frame
                            )
                            if self._first_endgame_sentinel_slot is None:
                                for team in self._sorted_teams():
                                    if team.player_id == sender_player.player_id:
                                        self._first_endgame_sentinel_slot = team.slot
                                        break
                    if self.config.game_c2_relay == "gameplay" and self._game_started:
                        if (
                            sender_player is not None
                            and sender_player.player_id != self._host_player.player_id
                            and not self._c2_stop_relay
                        ):
                            await self._echo_host_loading_sync(
                                game_frame,
                                body,
                                sender_writer=writer,
                                unknown=unknown,
                            )
                            if (
                                is_gamenet_transport_body(body)
                                and self._use_gamenet_host_fanout()
                            ):
                                await self._gamenet_host_fanout(
                                    sender_player,
                                    game_frame,
                                    body,
                                    exclude=writer,
                                )
                            else:
                                await self._relay_c2_to_peers(
                                    sender_player,
                                    game_frame,
                                    body,
                                    exclude=writer,
                                    unknown=unknown,
                                )
                        # Intentionally do not inject synthetic c00d... frames during endgame.
                        if self._should_stop_c2_relay(game_frame, body):
                            self._c2_stop_relay = True
                    if (
                        sender_player is not None
                        and sender_player.player_id != self._host_player.player_id
                        and body == C2_ENDGAME_SENTINEL
                    ):
                        expected = self._expected_human_player_ids()
                        try:
                            await self._maybe_synthesize_missing_endgame_sentinels()
                        except Exception as exc:
                            LOGGER.warning(
                                "WA endgame sentinel synthesis failed nick=%s: %s",
                                sender_player.nickname,
                                exc,
                            )
                        if expected and not expected.issubset(self._human_endgame_sentinels):
                            LOGGER.info(
                                "WA endgame sentinel from nick=%s roster=%s; waiting for %s; %s",
                                sender_player.nickname,
                                sender_player.player_id,
                                sorted(expected - self._human_endgame_sentinels),
                                self._endgame_net.status_summary()
                                if self._endgame_net is not None
                                else "endgame_net=off",
                            )
                        self._infer_winner_from_recent_game_frames()
                    elif not (self.config.game_c2_relay == "gameplay" and self._game_started):
                        # Pre-SRV_START loading only; gameplay relay path above handles in-game.
                        if (
                            sender_player is not None
                            and sender_player.player_id != self._host_player.player_id
                            and (
                                1 <= game_frame <= WA_LOADING_LAST_INDEX
                                or game_frame == WA_LOADING_DONE_FRAME
                                or (game_frame == 0x1C and len(body) > 8)
                            )
                        ):
                            await self._echo_host_loading_sync(
                                game_frame,
                                body,
                                sender_writer=writer,
                                unknown=unknown,
                            )
                            if (
                                is_gamenet_transport_body(body)
                                and self._use_gamenet_host_fanout()
                            ):
                                await self._gamenet_host_fanout(
                                    sender_player,
                                    game_frame,
                                    body,
                                    exclude=writer,
                                )
                            else:
                                await self._relay_c2_to_peers(
                                    sender_player,
                                    game_frame,
                                    body,
                                    exclude=writer,
                                    unknown=unknown,
                                )
                else:
                    LOGGER.info(
                        "WA unknown channel packet from %s channel=0x%02X cmd=0x%02X len=%s body=%s",
                        peer,
                        channel,
                        command,
                        packet_len,
                        _body_preview(body),
                    )
                    self._capture_packet(
                        direction="in",
                        channel=channel,
                        peer=peer,
                        nickname=player_nick,
                        command=command,
                        body=body,
                    )
        except asyncio.IncompleteReadError:
            LOGGER.info("WA client disconnected: %s nick=%s", peer, player_nick)
        except Exception as exc:
            LOGGER.warning("WA session error from %s nick=%s: %s", peer, player_nick, exc)
        finally:
            removed = self._remove_player(writer)
            removed_player: LobbyPlayer | None = None
            removed_teams: list[LobbyTeam] = []
            if removed is not None:
                removed_player, removed_teams = removed
                LOGGER.info("WA player left lobby: %s id=%s", removed_player.nickname, removed_player.player_id)
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
            self._client_writers.discard(writer)
            self._writer_send_locks.pop(writer, None)
            if task is not None:
                self._client_tasks.discard(task)
            if removed_player is not None and self._client_writers:
                with contextlib.suppress(Exception):
                    for removed_team in removed_teams:
                        await self._broadcast_team_removed(removed_team)
                    await self._broadcast_player_left(removed_player)
                    await self._broadcast_lobby_state()
            elif self._game_started and not self._client_writers:
                LOGGER.info("WA game ended: last client left, closing started session")
                with contextlib.suppress(Exception):
                    await self._finish_started_game()
