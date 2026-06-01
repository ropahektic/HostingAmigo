"""Unit tests for OpenWA-aligned endgame handshake tracker."""

from wormnetbot.endgame_net import (
    C2_ENDGAME_LOBBY_RETURN_PREFIX,
    C2_ENDGAME_SENTINEL,
    EndgameNetState,
    EndgamePhase,
)


def test_rank_surrender_sequence_two_peers() -> None:
    net = EndgameNetState(frozenset({1, 2}))
    assert net.phase == EndgamePhase.IDLE

    net.observe_incoming(1, b"\x5c\x1f\x02\x02" + b"\x00" * 8)
    assert net.phase == EndgamePhase.NETWORK_END_STARTED
    assert net.peers[1].saw_5c1f_burst

    net.observe_incoming(1, b"\x40\x02\x04\x14\x03\x0c\x1e")
    assert net.phase == EndgamePhase.ROUND_ENDING

    net.observe_incoming(1, C2_ENDGAME_SENTINEL)
    assert net.peers[1].sent_400600
    assert not net.all_sent_400600

    net.observe_incoming(2, C2_ENDGAME_SENTINEL)
    assert net.all_sent_400600

    net.observe_incoming(1, C2_ENDGAME_LOBBY_RETURN_PREFIX + b"\x01")
    net.observe_incoming(2, C2_ENDGAME_LOBBY_RETURN_PREFIX + b"\x01")
    assert net.phase == EndgamePhase.COMPLETE
    assert not net.should_keep_relaying()
