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
from typing import Awaitable, Callable

from .config import BotConfig


LOGGER = logging.getLogger(__name__)

LOBBY_CHANNEL = 0x01
GAME_CHANNEL = 0x02

CMD_CHAT = 0x00
CMD_LOGIN = 0x04
CMD_LOGIN2 = 0x05
CMD_READY = 0x0F
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
SRV_READY = 0x0F
SRV_TEAM_COLOR = 0x16
SRV_TEAM_HANDICAP = 0x17
SRV_TEAM_WORMS = 0x18
SRV_START_GAME = 0x1C
SRV_TEAM_ADD = 0x1A
SRV_DEFAULT_SCHEME = 0x1F
SRV_RANDOM_MAP = 0x21

WA_HEADER = struct.Struct("<BBHBB")
WA_FRAME_HEADER = struct.Struct("<BBHBI")
WA_PACKET_PREFIX = struct.Struct("<BBH")
WA_LOBBY_REST = struct.Struct("<BB")
WA_GAME_REST = struct.Struct("<BI")

# First end-of-round body in captured channel-2 streams; after this, mirroring must stop.
C2_ENDGAME_SENTINEL = b"\x40\x06\x00"

PLAYER_SLOT_COUNT = 7
PLAYER_NAME_SIZE = 17
PLAYER_STRUCT_SIZE = 120
PLAYER_LIST_PADDING_SIZE = 0x2D0

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
    if prefix[:4] not in {"401e", "401f", "4021", "441f"}:
        return None
    if prefix[6:8] not in {"02", "1e"}:
        return None
    try:
        slot = int(prefix[4:6], 16)
    except ValueError:
        return None
    return slot if slot > 0 else None


ENDGAME_SLOT_BODY_MARKERS: dict[int, frozenset[str]] = {
    1: frozenset(
        {
            "6002020000",
            "7402020000",
            "540200032001502015020c1e84e8370000",
            "540200030c1e60980401f07a0000",
            "401f02020ccc050c1e021008a6c000",
        }
    ),
    2: frozenset(
        {
            "4402020000",
            "400204060000",
            "40020400050c1e0301601b144000",
        }
    ),
}

ENDGAME_SLOT_FAMILY_MARKERS: dict[int, frozenset[str]] = {
    1: frozenset(
        {
            "401f0102",
            "401e0102/0c24050c",
            "401e0102/0c60050c",
            "401e0102/0c78050c",
            "54020003",
            "40210102",
            "40200102",
            "40022001",
            "5c1e0102",
            "5c02000b",
            "44020001",
            "401f0202/0ccc050c",
        }
    ),
    2: frozenset(
        {
            "401e0202",
            "401e0102/0ccc050c",
            "5c020001",
            "44020200",
            "48020200",
            "54020200",
            "40020406",
            "4021021f",
            "40210202",
            "60020003",
            "64020003",
            "401f0202/0c3ec020",
            "c01f0204",
            "e00c1e03",
        }
    ),
}


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
    return _pack_lobby(SRV_CUSTOM_SCHEME, payload)


def _pack_team_add(payload: bytes) -> bytes:
    return _pack_lobby(SRV_TEAM_ADD, payload)


def _pack_lobby_command(command: int, payload: bytes) -> bytes:
    return _pack_lobby(command, payload)


def _pack_team_color(slot: int, color: int) -> bytes:
    return _pack_lobby(SRV_TEAM_COLOR, struct.pack("<HII", 0, slot, color))


def _pack_ready(player_id: int, ready: bool) -> bytes:
    payload = struct.pack("<HII", 0, 1 if ready else 0, player_id)
    return _pack_lobby(SRV_READY, payload)


def _pack_start_game(logic_seed: int, game_version: int = 0x4C) -> bytes:
    payload = struct.pack("<HI4sI", 0, logic_seed, b"GSAW", game_version)
    return _pack_lobby(SRV_START_GAME, payload)


def _pack_game_frame(player_id: int, frame: int, payload: bytes, *, unknown: int = 0) -> bytes:
    return WA_FRAME_HEADER.pack(GAME_CHANNEL, unknown, WA_FRAME_HEADER.size + len(payload), player_id, frame) + payload


def _pack_loading_frame(player_id: int, frame: int) -> bytes:
    payload = struct.pack("<HH", 0x0AC0, (frame - 1) * 4)
    return _pack_game_frame(player_id, frame, payload)


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


def _pack_player_slot(nickname: str, country: int, previous_player_id: int, *, is_host: bool) -> bytes:
    slot = bytearray(PLAYER_STRUCT_SIZE)
    slot[0:PLAYER_NAME_SIZE] = _encode_fixed_string(nickname, PLAYER_NAME_SIZE)
    profile = HOST_PLAYER_PROFILE if is_host else GUEST_PLAYER_PROFILE
    slot[17 : 17 + len(profile)] = profile
    struct.pack_into("<h", slot, 108, previous_player_id)
    slot[112] = country & 0xFF
    # Real WA hosts send these flag bytes as 1/1 in the initial lobby list.
    slot[116] = 1
    slot[117] = 1
    return bytes(slot)


def _pack_player_list(players: list[LobbyPlayer]) -> bytes:
    payload = bytearray()
    payload.extend(b"\x00\x00\x01\x00\x00\x00")
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
            )
        )
        previous_player_id = player.player_id
    payload.extend(b"\x00" * PLAYER_LIST_PADDING_SIZE)
    payload.extend(struct.pack("<HH", len(players), 0))
    return _pack_lobby(SRV_PLAYER_LIST, bytes(payload))


def _pack_team_list(team: LobbyTeam) -> bytes:
    payload = bytearray(TEAM_STRUCT_SIZE)
    struct.pack_into("<H", payload, 2, team.slot)
    payload[6] = team.player_id & 0xFF
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


def _parse_login2(body: bytes) -> tuple[str, int]:
    nickname = _decode_c_string(body[0:17])
    country = body[66] if len(body) > 66 else 15
    return nickname, country


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


class GameSession:
    def __init__(self, config: BotConfig, scheme: str) -> None:
        self.config = config
        self.scheme = scheme
        self.custom_scheme_payload = CUSTOM_SCHEME_PAYLOADS.get(scheme.strip().lower())
        self.scheme_id = -1 if self.custom_scheme_payload is not None else 2
        self._server: asyncio.base_events.Server | None = None
        self._client_tasks: set[asyncio.Task[None]] = set()
        self._client_writers: set[asyncio.StreamWriter] = set()
        self._join_attempts = 0
        self._game_started = False
        self.on_game_started: Callable[[], Awaitable[None]] | None = None
        self.on_game_ended: Callable[[], Awaitable[None]] | None = None
        self._host_loading_frames_sent: set[int] = set()
        self._c2_stop_relay: bool = False
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
        self._recent_incoming_game_frames: list[tuple[int, bytes]] = []
        self._winner_team_name: str | None = None
        self._winner_player_nickname: str | None = None
        self._winner_reason: str | None = None
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
        self._host_loading_frames_sent.clear()
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

    def _allocate_player_id(self) -> int | None:
        for player_id in range(1, PLAYER_SLOT_COUNT):
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
    ) -> None:
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
            }
        )

    def _remember_incoming_game_frame(self, frame: int, body: bytes) -> None:
        self._recent_incoming_game_frames.append((frame, bytes(body)))
        if len(self._recent_incoming_game_frames) > 64:
            del self._recent_incoming_game_frames[: len(self._recent_incoming_game_frames) - 64]

    def _infer_winner_from_recent_game_frames(self) -> None:
        if self._winner_team_name is not None:
            return

        candidate_teams = [
            team
            for team in self._sorted_teams()
            if team.player_id != self._host_player.player_id and not team.name.endswith("'s team")
        ]
        if not candidate_teams:
            return

        recent_hex = [
            body.hex()
            for _, body in self._recent_incoming_game_frames[-16:]
            if body and body != C2_ENDGAME_SENTINEL
        ]
        if not recent_hex:
            return

        endgame_window = [
            (frame, body)
            for frame, body in self._recent_incoming_game_frames[-16:]
            if body and body != C2_ENDGAME_SENTINEL
        ]
        family_window = [
            {
                "frame": frame,
                "body_hex": body.hex(),
                "family": _packet_family(body),
            }
            for frame, body in endgame_window
        ]

        if len(candidate_teams) > 2:
            teams_by_slot = {team.slot: team for team in candidate_teams}
            slot_scores = {team.slot: 0 for team in candidate_teams}
            reasons: list[str] = []
            total = len(family_window)
            for index, packet in enumerate(family_window):
                rel_index = index - total
                weight = max(1, index + 1)
                family = str(packet["family"])
                slot = _slot_from_endgame_family(family)
                if slot not in teams_by_slot:
                    continue
                score = 3 + weight
                slot_scores[slot] += score
                reasons.append(f"slot{slot}:family:{family}@{rel_index}")

            ranked = sorted(slot_scores.items(), key=lambda item: item[1], reverse=True)
            best_slot, best_score = ranked[0]
            second_score = ranked[1][1] if len(ranked) > 1 else 0
            if best_score < 6 or best_score - second_score < 3:
                LOGGER.info(
                    "WA multi-team winner inference inconclusive: scores=%s recent=%s",
                    slot_scores,
                    recent_hex,
                )
                return

            winner = teams_by_slot[best_slot]
            winner_player_nickname = self._player_nickname_for_team(winner)
            self._winner_team_name = winner.name
            self._winner_player_nickname = winner_player_nickname
            self._winner_reason = "endgame-family-multiteam"
            LOGGER.info(
                "WA probable multi-team winner inferred: team=%s player=%s slot=%s owner_player_id=%s scores=%s reasons=%s recent=%s",
                winner.name,
                winner_player_nickname or "<unknown>",
                winner.slot,
                winner.player_id,
                slot_scores,
                ",".join(reasons),
                recent_hex,
            )
            self._append_capture(
                {
                    "type": "winner_inferred",
                    "team_name": winner.name,
                    "team_slot": winner.slot,
                    "player_id": winner.player_id,
                    "player_nickname": winner_player_nickname,
                    "slot_scores": slot_scores,
                    "reasons": reasons,
                    "families": family_window,
                    "recent_bodies": recent_hex,
                }
            )
            return

        slot_scores = {1: 0, 2: 0}
        reasons: list[str] = []
        family_counts = {1: 0, 2: 0}
        total = len(family_window)
        for index, packet in enumerate(family_window):
            rel_index = index - total
            weight = max(1, index + 1)
            body_hex = str(packet["body_hex"])
            family = str(packet["family"])
            for slot in (1, 2):
                if body_hex in ENDGAME_SLOT_BODY_MARKERS[slot]:
                    score = 8 + weight
                    slot_scores[slot] += score
                    reasons.append(f"slot{slot}:body:{body_hex}@{rel_index}")
                family_prefix = family.split("/", 1)[0]
                if family in ENDGAME_SLOT_FAMILY_MARKERS[slot] or family_prefix in ENDGAME_SLOT_FAMILY_MARKERS[slot]:
                    slot_scores[slot] += 2 + weight
                    family_counts[slot] += 1
                    reasons.append(f"slot{slot}:family:{family}@{rel_index}")

        first_score = slot_scores[1]
        second_score = slot_scores[2]
        if max(first_score, second_score) < 6 or abs(first_score - second_score) < 3:
            LOGGER.info(
                "WA winner inference inconclusive: slot1=%s slot2=%s family_hits=%s recent=%s",
                first_score,
                second_score,
                family_counts,
                recent_hex,
            )
            return

        winner = candidate_teams[0] if first_score > second_score else candidate_teams[1]
        winner_player_nickname = self._player_nickname_for_team(winner)
        self._winner_team_name = winner.name
        self._winner_player_nickname = winner_player_nickname
        self._winner_reason = "endgame-family"
        LOGGER.info(
            "WA probable winner inferred: team=%s player=%s slot=%s owner_player_id=%s slot1=%s slot2=%s family_hits=%s reasons=%s recent=%s",
            winner.name,
            winner_player_nickname or "<unknown>",
            winner.slot,
            winner.player_id,
            first_score,
            second_score,
            family_counts,
            ",".join(reasons),
            recent_hex,
        )
        self._append_capture(
            {
                "type": "winner_inferred",
                "team_name": winner.name,
                "team_slot": winner.slot,
                "player_id": winner.player_id,
                "player_nickname": winner_player_nickname,
                "slot1_score": first_score,
                "slot2_score": second_score,
                "family_hits": family_counts,
                "reasons": reasons,
                "families": family_window,
                "recent_bodies": recent_hex,
            }
        )

    async def _send_packets(self, writer: asyncio.StreamWriter, *packets: bytes) -> None:
        for packet in packets:
            writer.write(packet)
        await writer.drain()

    async def _send_full_state(self, writer: asyncio.StreamWriter) -> None:
        players = self._sorted_players()
        packets: list[bytes] = [
            _pack_player_list(players),
        ]
        if self.custom_scheme_payload is not None:
            packets.append(_pack_custom_scheme(self.custom_scheme_payload))
        else:
            packets.append(_pack_default_scheme(self.scheme_id))
        packets.append(_pack_random_map(self._map_seed1, self._map_seed2))
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

    async def _broadcast_lobby_state(self, exclude: asyncio.StreamWriter | None = None) -> None:
        players = self._sorted_players()
        packets: list[bytes] = [_pack_player_list(players)]
        for writer in list(self._client_writers):
            if writer is exclude:
                continue
            try:
                await self._send_packets(writer, *packets)
            except Exception as exc:
                LOGGER.warning("Failed to broadcast lobby state: %s", exc)

    async def _broadcast_ready(self, player: LobbyPlayer) -> None:
        packet = _pack_ready(player.player_id, player.ready)
        for writer in list(self._client_writers):
            try:
                self._capture_packet(
                    direction="out",
                    channel=LOBBY_CHANNEL,
                    peer=writer.get_extra_info("peername"),
                    nickname=player.nickname,
                    command=SRV_READY,
                    body=packet[WA_HEADER.size :],
                )
                await self._send_packets(writer, packet)
            except Exception as exc:
                LOGGER.warning("Failed to broadcast ready state: %s", exc)

    async def _broadcast_team_add(self, payload: bytes) -> None:
        packet = _pack_team_add(payload)
        for writer in list(self._client_writers):
            try:
                self._capture_packet(
                    direction="out",
                    channel=LOBBY_CHANNEL,
                    peer=writer.get_extra_info("peername"),
                    nickname=None,
                    command=SRV_TEAM_ADD,
                    body=payload,
                )
                await self._send_packets(writer, packet)
            except Exception as exc:
                LOGGER.warning("Failed to broadcast team add: %s", exc)

    async def _broadcast_lobby_command(self, command: int, payload: bytes) -> None:
        packet = _pack_lobby_command(command, payload)
        for writer in list(self._client_writers):
            try:
                self._capture_packet(
                    direction="out",
                    channel=LOBBY_CHANNEL,
                    peer=writer.get_extra_info("peername"),
                    nickname=None,
                    command=command,
                    body=payload,
                )
                await self._send_packets(writer, packet)
            except Exception as exc:
                LOGGER.warning("Failed to broadcast lobby command 0x%02X: %s", command, exc)

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

    async def start_game(self) -> None:
        if self._game_started:
            return
        self._game_started = True
        self._host_loading_frames_sent.clear()
        self._c2_stop_relay = False
        self._recent_incoming_game_frames.clear()
        self._winner_team_name = None
        self._winner_player_nickname = None
        self._winner_reason = None
        packets = [_pack_start_game(self._logic_seed)]
        LOGGER.info(
            "WA start game: logic_seed=0x%08X players=%s clients=%s",
            self._logic_seed,
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
        self._host_loading_frames_sent.clear()
        self._game_started = False
        self._finish_capture("game_ended")
        if self.on_game_ended is not None:
            try:
                await self.on_game_ended()
            except Exception as exc:
                LOGGER.warning("Failed game-ended callback: %s", exc)

    async def _send_host_game_frame(self, frame: int, payload: bytes) -> None:
        packet = _pack_game_frame(self._host_player.player_id, frame, payload)
        LOGGER.info(
            "WA host game frame player=%s frame=0x%08X body=%s",
            self._host_player.player_id,
            frame,
            _body_preview(payload),
        )
        for writer in list(self._client_writers):
            try:
                self._capture_packet(
                    direction="out",
                    channel=GAME_CHANNEL,
                    peer=writer.get_extra_info("peername"),
                    nickname=self._host_player.nickname,
                    command=self._host_player.player_id,
                    frame=frame,
                    body=payload,
                )
                await self._send_packets(writer, packet)
            except Exception as exc:
                LOGGER.warning("Failed to send host game frame: %s", exc)

    def _remove_player(self, writer: asyncio.StreamWriter) -> LobbyPlayer | None:
        player = self._players_by_writer.pop(writer, None)
        if player is None:
            return None
        self._players_by_id.pop(player.player_id, None)
        if player.team_slot is not None:
            self._teams_by_slot.pop(player.team_slot, None)
        return player

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
                elif channel == GAME_CHANNEL:
                    if packet_len < WA_FRAME_HEADER.size:
                        raise RuntimeError(
                            f"Invalid WA game packet length: {packet_len} "
                            f"prefix={prefix.hex(' ')} channel=0x{channel:02X} unknown=0x{unknown:02X}"
                        )
                    header_rest = await reader.readexactly(WA_GAME_REST.size)
                    command, game_frame = WA_GAME_REST.unpack(header_rest)
                    body = await reader.readexactly(packet_len - WA_FRAME_HEADER.size)
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
                        )
                        lowered = text.strip().lower()
                        if lowered == "!ready":
                            await self.set_host_ready(True)
                            await self._broadcast_chat("Rbot is ready.")
                        elif lowered == "!start":
                            await self.start_game()
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
                    elif command == CMD_LOGIN:
                        self._join_attempts += 1
                        player_nick, game_name, version = _parse_login(body)
                        LOGGER.info(
                            "WA join step1 from %s nick=%s game=%s version=%s",
                            peer,
                            player_nick,
                            game_name or "<ip-game>",
                            version.hex(" "),
                        )
                        writer.write(_pack_login_ok())
                        await writer.drain()
                    elif command == CMD_LOGIN2:
                        player_nick, country = _parse_login2(body)
                        player = self._players_by_writer.get(writer)
                        if player is None:
                            player_id = self._allocate_player_id()
                            if player_id is None:
                                LOGGER.warning("Rejecting WA join from %s nick=%s: lobby full", peer, player_nick)
                                writer.write(_pack_login_error())
                                await writer.drain()
                                return
                            player = LobbyPlayer(
                                player_id=player_id,
                                nickname=player_nick,
                                country=country,
                                writer=writer,
                            )
                            team = self._build_default_team(player)
                            player.team_slot = team.slot
                            self._players_by_writer[writer] = player
                            self._players_by_id[player.player_id] = player
                            self._teams_by_slot[team.slot] = team
                        else:
                            player.nickname = player_nick
                            player.country = country
                        LOGGER.info(
                            "WA join step2 from %s nick=%s player=%s country=%s scheme=%s(%s)",
                            peer,
                            player_nick,
                            player.player_id,
                            country,
                            self.scheme,
                            self.scheme_id,
                        )
                        await self._send_full_state(writer)
                        await self._broadcast_lobby_state(exclude=writer)
                    elif command == CMD_READY:
                        ready = len(body) >= 10 and struct.unpack_from("<I", body, 2)[0] != 0
                        player_id = struct.unpack_from("<I", body, 6)[0] if len(body) >= 10 else 0
                        player = self._players_by_writer.get(writer)
                        if player is not None:
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
                            writer.write(_pack_ready(player_id, ready))
                            await writer.drain()
                    elif command == CMD_TEAM_ADD:
                        player = self._players_by_writer.get(writer)
                        team = _parse_team_add_payload(body)
                        if player is not None:
                            # The most reliable owner signal is the socket that sent the
                            # editable team packet, not the ambiguous player byte inside
                            # the payload.
                            team.player_id = player.player_id
                        existing_by_name = next(
                            (existing for existing in self._editable_teams if existing.name == team.name),
                            None,
                        )
                        if existing_by_name is not None:
                            team.slot = existing_by_name.slot
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
                        await self._broadcast_team_add(body)
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
                        await self._broadcast_lobby_command(command, body)
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
                    )
                    if command != self._host_player.player_id:
                        self._remember_incoming_game_frame(game_frame, body)
                        if body == C2_ENDGAME_SENTINEL:
                            self._infer_winner_from_recent_game_frames()
                    if self.config.game_c2_relay == "gameplay" and self._game_started:
                        if body == C2_ENDGAME_SENTINEL:
                            self._c2_stop_relay = True
                        if not self._c2_stop_relay and command != self._host_player.player_id:
                            if 1 <= game_frame <= 0x1A:
                                if game_frame not in self._host_loading_frames_sent:
                                    self._host_loading_frames_sent.add(game_frame)
                                    await self._send_host_game_frame(
                                        game_frame,
                                        struct.pack("<HH", 0x0AC0, (game_frame - 1) * 4),
                                    )
                            elif game_frame == 0x0200001B:
                                await self._send_host_game_frame(game_frame, body)
                            else:
                                await self._send_host_game_frame(game_frame, body)
                    else:
                        if 1 <= game_frame <= 0x1A and command != self._host_player.player_id:
                            if game_frame not in self._host_loading_frames_sent:
                                self._host_loading_frames_sent.add(game_frame)
                                await self._send_host_game_frame(
                                    game_frame,
                                    struct.pack("<HH", 0x0AC0, (game_frame - 1) * 4),
                                )
                        elif game_frame == 0x0200001B and command != self._host_player.player_id:
                            await self._send_host_game_frame(game_frame, body)
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
            removed_player = self._remove_player(writer)
            if removed_player is not None:
                LOGGER.info("WA player left lobby: %s id=%s", removed_player.nickname, removed_player.player_id)
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
            self._client_writers.discard(writer)
            if task is not None:
                self._client_tasks.discard(task)
            if removed_player is not None and self._client_writers:
                with contextlib.suppress(Exception):
                    await self._broadcast_lobby_state()
            elif self._game_started and not self._client_writers:
                LOGGER.info("WA game ended: last client left, closing started session")
                with contextlib.suppress(Exception):
                    await self._finish_started_game()
