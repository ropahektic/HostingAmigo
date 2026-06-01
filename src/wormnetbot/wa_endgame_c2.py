"""Shared channel-2 endgame body classification (no game_host import)."""

from __future__ import annotations

C2_ENDGAME_SENTINEL = b"\x40\x06\x00"
C2_ENDGAME_LOBBY_RETURN_PREFIX = b"\xc0\x0d"
C2_5C1F_CONTAINER_PREFIX = b"\x5c\x1f\x02\x02"

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

_ENDGAME_FANFARE_OTHER_PREFIXES = (
    b"\x50\x02",
    b"\x74\x02",
    b"\x48\x02",
    b"\x6c\x02",
    b"\x78\x02",
    b"\x7c\x02",
    b"\xd4\x02",
    b"\x64\x1e",
)


def is_endgame_fanfare_c2_body(body: bytes) -> bool:
    """True for msg_save fanfare / surrender containers — not routine turn 400204 sync."""
    if not body:
        return False
    if body.startswith(C2_5C1F_CONTAINER_PREFIX):
        return True
    if body.startswith(_ENDGAME_FANFARE_PREFIXES):
        return True
    if body.startswith(_ENDGAME_FANFARE_OTHER_PREFIXES):
        return True
    return False
