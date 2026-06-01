"""GameNet transport helpers for RBot channel-2 relay.

OpenWA rank sessions use **star topology**: clients send GameNet only to peer 0 (host);
the host must fan out each packet to every other peer (`WS_GameNet__ReceivePacket`).

Do **not** rewrite bytes inside ``c0 70`` / ``40 70`` LZ77 blobs — byte 2 is message
framing, not a relay remap target (prior remap caused desync at game start).
"""

from __future__ import annotations

import logging
from collections import deque
from dataclasses import dataclass, field

LOGGER = logging.getLogger(__name__)

_GAMENET_HI = frozenset(range(0x70, 0x74))

# High frame index band used by GameNet on channel 2 (not the loading ladder 0x1..0x1C).
DEFAULT_GAMENET_FRAME = 0x20000020

# Short captured GameNet body (22 B, rank load). Host mask uses peer-byte 0x01 until
# LZ77 mask generation is reproduced from `WS_GameNet__update_mask`.
_HOST_MASK_TEMPLATE = bytes.fromhex(
    "c070110202950100005eeb473c310000009dc6f2bc00"
)


def is_gamenet_transport_body(body: bytes) -> bool:
    """Heuristic marker for GameNet-shaped channel-2 bodies."""
    if len(body) < 2:
        return False
    return body[0] in (0x40, 0xC0) and body[1] in _GAMENET_HI


def remap_gamenet_body_for_receiver(body: bytes, *, sender_wire: int) -> bytes:
    """Passthrough — peer-byte rewrite was incorrect for this wire format."""
    _ = sender_wire
    return body


def host_mask_gamenet_body() -> bytes:
    """Wire-ready host connection-mask packet (best-effort from corpus + OpenWA RE)."""
    if len(_HOST_MASK_TEMPLATE) < 3:
        return _HOST_MASK_TEMPLATE
    out = bytearray(_HOST_MASK_TEMPLATE)
    out[2] = 0x01
    return bytes(out)


def gamenet_frame_for_host(anchor_frame: int) -> int:
    """Pick a channel-2 frame index in the GameNet band (never loading frame 0x1)."""
    if anchor_frame >= 0x100000:
        return anchor_frame
    return DEFAULT_GAMENET_FRAME


@dataclass
class EndgameHandshakeAssist:
    """Buffers GameNet frames and triggers host assist at network end."""

    _recent_by_player: dict[int, deque[tuple[int, bytes]]] = field(default_factory=dict)
    _kick_started: bool = False
    _max_recent: int = 12

    def reset(self) -> None:
        self._recent_by_player.clear()
        self._kick_started = False

    def observe(self, player_id: int, frame: int, body: bytes) -> None:
        if not is_gamenet_transport_body(body):
            return
        q = self._recent_by_player.setdefault(player_id, deque(maxlen=self._max_recent))
        q.append((frame, bytes(body)))

    async def maybe_kick(self, session: object, *, reason: str) -> None:
        if self._kick_started:
            return
        kick = getattr(session, "_endgame_gamenet_kick", None)
        if kick is None:
            LOGGER.warning("WA endgame GameNet kick unavailable on session (%s)", reason)
            return
        self._kick_started = True
        LOGGER.info("WA endgame GameNet host assist requested (%s)", reason)
        try:
            await kick(reason=reason)
        except Exception as exc:
            self._kick_started = False
            LOGGER.warning(
                "WA endgame GameNet kick failed (%s): %s",
                reason,
                exc,
                exc_info=True,
            )
