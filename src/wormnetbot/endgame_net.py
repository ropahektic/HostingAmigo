"""OpenWA-aligned channel-2 endgame handshake tracker for RBot."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum

from .wa_endgame_c2 import (
    C2_5C1F_CONTAINER_PREFIX,
    C2_ENDGAME_LOBBY_RETURN_PREFIX,
    C2_ENDGAME_SENTINEL,
    is_endgame_fanfare_c2_body,
)
from .wa_task_stream import count_400204_ladder_frames


class EndgamePhase(IntEnum):
    IDLE = 0
    NETWORK_END_STARTED = 3
    NETWORK_END_AWAITING_PEERS = 2
    ROUND_ENDING = 4
    COMPLETE = 5


@dataclass(slots=True)
class PeerEndgameFlags:
    player_id: int
    saw_5c1f_burst: bool = False
    ladder_400204_frames: int = 0
    sent_400600: bool = False
    sent_c00d: bool = False

    def to_capture_dict(self) -> dict[str, object]:
        return {
            "player_id": self.player_id,
            "saw_5c1f": self.saw_5c1f_burst,
            "ladder_400204_frames": self.ladder_400204_frames,
            "sent_400600": self.sent_400600,
            "sent_c00d": self.sent_c00d,
        }


@dataclass
class EndgameNetState:
    human_player_ids: frozenset[int]
    phase: EndgamePhase = EndgamePhase.IDLE
    entered_round_ending_without_net_end: bool = False
    peers: dict[int, PeerEndgameFlags] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for player_id in self.human_player_ids:
            self.peers.setdefault(player_id, PeerEndgameFlags(player_id=player_id))

    def observe_incoming(self, player_id: int, body: bytes) -> EndgamePhase | None:
        if player_id not in self.human_player_ids or not body:
            return None
        prior = self.phase
        peer = self.peers[player_id]

        if body.startswith(C2_5C1F_CONTAINER_PREFIX):
            peer.saw_5c1f_burst = True
            if self.phase == EndgamePhase.IDLE:
                self.phase = EndgamePhase.NETWORK_END_STARTED

        # Do not treat routine in-game 400204 turn sync as endgame (was false-positive
        # at match start and broke handshake assist / desynced clients).
        if is_endgame_fanfare_c2_body(body):
            if self.phase in (EndgamePhase.IDLE, EndgamePhase.NETWORK_END_STARTED):
                if self.phase == EndgamePhase.IDLE:
                    self.entered_round_ending_without_net_end = True
                self.phase = EndgamePhase.ROUND_ENDING
            ladder_steps = count_400204_ladder_frames(body)
            if ladder_steps:
                peer.ladder_400204_frames += ladder_steps

        if body == C2_ENDGAME_SENTINEL:
            peer.sent_400600 = True
            if self.phase < EndgamePhase.ROUND_ENDING:
                self.phase = EndgamePhase.ROUND_ENDING
            if self.all_sent_400600 and self.phase == EndgamePhase.ROUND_ENDING:
                self.phase = EndgamePhase.NETWORK_END_AWAITING_PEERS

        if body.startswith(C2_ENDGAME_LOBBY_RETURN_PREFIX):
            peer.sent_c00d = True
            if self.all_sent_c00d:
                self.phase = EndgamePhase.COMPLETE

        return self.phase if self.phase != prior else None

    @property
    def all_sent_400600(self) -> bool:
        if not self.human_player_ids:
            return False
        return all(self.peers[pid].sent_400600 for pid in self.human_player_ids)

    @property
    def all_sent_c00d(self) -> bool:
        if not self.human_player_ids:
            return False
        return all(self.peers[pid].sent_c00d for pid in self.human_player_ids)

    def missing_400600_player_ids(self) -> set[int]:
        return {pid for pid in self.human_player_ids if not self.peers[pid].sent_400600}

    def missing_c00d_player_ids(self) -> set[int]:
        return {pid for pid in self.human_player_ids if not self.peers[pid].sent_c00d}

    def should_keep_relaying(self) -> bool:
        return self.phase != EndgamePhase.COMPLETE

    def status_summary(self) -> str:
        parts = [f"phase={self.phase.name}"]
        for pid in sorted(self.human_player_ids):
            p = self.peers[pid]
            parts.append(
                f"p{pid}(5c1f={int(p.saw_5c1f_burst)} ladder={p.ladder_400204_frames} "
                f"600={int(p.sent_400600)} c00d={int(p.sent_c00d)})"
            )
        return " ".join(parts)

    def to_capture_dict(self) -> dict[str, object]:
        return {
            "phase": self.phase.name,
            "phase_value": int(self.phase),
            "all_sent_400600": self.all_sent_400600,
            "all_sent_c00d": self.all_sent_c00d,
            "entered_round_ending_without_net_end": self.entered_round_ending_without_net_end,
            "peers": [self.peers[pid].to_capture_dict() for pid in sorted(self.human_player_ids)],
        }
