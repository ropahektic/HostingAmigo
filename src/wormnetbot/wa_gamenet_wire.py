"""Build / parse GameNet channel-2 ``c070`` / ``4070`` envelopes (rank captures)."""

from __future__ import annotations

import struct
from dataclasses import dataclass

from .wa_lz77 import lz77_compress_maybe

GAMENET_HI = 0x70
DIR_CLIENT = 0xC0
DIR_RELAY = 0x40

SUBTYPE_HOST_MASK = 0x02
SUBTYPE_GAME_BLOB = 0x06

# 22 B host mask from rank load (`c070 01 02 …`).
_HOST_MASK_TEMPLATE = bytes.fromhex(
    "c070010202950100005eeb473c310000009dc6f2bc00"
)

# Fixed prefix for synthetic wrap experiments only (session bytes from one capture).
_CAPTURE_SESSION_PREFIX = bytes.fromhex("06b3ea150176308aca64055b4326a031")


@dataclass(frozen=True, slots=True)
class C070Envelope:
    """Parsed channel-2 GameNet envelope (subtype 0x06 load blob or 0x02 mask)."""

    direction: int
    peer_byte: int
    subtype: int
    game_key: int
    session_id: bytes
    payload: bytes
    raw: bytes

    @property
    def is_host_mask(self) -> bool:
        return self.subtype == SUBTYPE_HOST_MASK and len(self.raw) == 22

    @property
    def is_game_blob(self) -> bool:
        return self.subtype == SUBTYPE_GAME_BLOB and len(self.session_id) == 14


def is_gamenet_transport_body(body: bytes) -> bool:
    if len(body) < 2:
        return False
    # Byte 0 is direction (0xC0 client, 0x40/0x44 host relay); byte 1 is always 0x70.
    return body[1] == GAMENET_HI and (body[0] & 0xF0) in (DIR_CLIENT, DIR_RELAY)


def parse_c070_envelope(body: bytes) -> C070Envelope | None:
    """Parse ``c070`` / ``4070`` layout from rank captures."""
    if not is_gamenet_transport_body(body):
        return None
    if len(body) < 4:
        return None
    subtype = body[3]
    if subtype == SUBTYPE_HOST_MASK:
        if len(body) != 22:
            return None
        return C070Envelope(
            direction=body[0],
            peer_byte=body[2],
            subtype=subtype,
            game_key=body[4] if len(body) > 4 else 0,
            session_id=b"",
            payload=body[4:-1] if body.endswith(b"\x00") else body[4:],
            raw=body,
        )
    if subtype != SUBTYPE_GAME_BLOB or len(body) < 20:
        return None
    session_id = body[5:19]
    end = len(body)
    if body.endswith(b"\x00"):
        end -= 1
    payload = body[19:end]
    return C070Envelope(
        direction=body[0],
        peer_byte=body[2],
        subtype=subtype,
        game_key=body[4],
        session_id=session_id,
        payload=payload,
        raw=body,
    )


def pack_net_header(*, peer: int, seq: int, tag: int = 0) -> bytes:
    """4-byte GameNet header inside WA (peer low nibble, tag high nibble, 24-bit seq)."""
    value = (peer & 0x0F) | ((tag & 0x0F) << 4) | ((seq & 0xFFFFFF) << 8)
    return struct.pack("<I", value)


def pack_machine_quit_staging(team_index: int) -> bytes:
    """12-byte staging for EntityMessage::MachineQuit (0x0D) before LZ77."""
    team = max(0, min(team_index, 0x0F))
    return bytes([0x0D, team, 1] + [0] * 9)


def pack_gamenet_lz77_payload(staging: bytes, *, peer: int, seq: int, tag: int = 0) -> bytes:
    """Header + LZ77(staging); LZ77 byte 0 is wire seed (0) — goes inside opaque payload, not c070[0]."""
    return pack_net_header(peer=peer, seq=seq, tag=tag) + lz77_compress_maybe(staging)


def wrap_c070_game_blob(
    inner_payload: bytes,
    *,
    peer_byte: int,
    game_key: int,
    session_id: bytes,
    direction: int = DIR_CLIENT,
) -> bytes:
    """Build subtype ``0x06`` envelope (host synthesis — inner_payload must match WA container)."""
    if len(session_id) != 14:
        raise ValueError("session_id must be 14 bytes")
    return (
        bytes([direction, GAMENET_HI, peer_byte & 0xFF, SUBTYPE_GAME_BLOB, game_key & 0xFF])
        + session_id
        + inner_payload
        + b"\x00"
    )


def host_mask_gamenet_body() -> bytes:
    """22 B host mask (subtype 0x02)."""
    if len(_HOST_MASK_TEMPLATE) != 22:
        return _HOST_MASK_TEMPLATE
    out = bytearray(_HOST_MASK_TEMPLATE)
    out[0] = DIR_CLIENT
    out[2] = 0x01
    return bytes(out)


def peer_byte_from_capture_template(template: bytes, roster_wire: int) -> int:
    """``(template[2] & 0xF0) | wire`` for per-client relay."""
    if len(template) >= 3:
        return ((template[2] & 0xF0) | (roster_wire & 0x0F)) & 0xFF
    return roster_wire & 0xFF


def build_host_machine_quit_c070(
    *,
    peer_byte: int,
    team_index: int,
    seq: int = 1,
    session_id: bytes | None = None,
    game_key: int = 0,
) -> bytes:
    """Experimental: wrap MachineQuit LZ77 in subtype 0x06 (inner container not validated)."""
    inner = pack_gamenet_lz77_payload(
        pack_machine_quit_staging(team_index), peer=0, seq=seq, tag=0
    )
    return wrap_c070_game_blob(
        inner,
        peer_byte=peer_byte,
        game_key=game_key,
        session_id=session_id or _CAPTURE_SESSION_PREFIX[1:15],
    )
