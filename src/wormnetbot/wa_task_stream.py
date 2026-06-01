"""
Parse serialized EntityMessage / TaskMessageType records from WA channel-2 bodies.

Canonical names: OpenWA ``re/entity/EntityMessage.toml`` (Surrender=0x2B, TeamVictory=0x14).
Ground truth (Ghidra WA.exe, EntityMessage__msg_expand @ 0x564EA0, msg_compress @ 0x5648B0):
- First stream byte ``v`` → ``TaskMessageType = v + 1000``.
- Type **1043** (``0x2B``): ``surrender_team`` / ``process_surrender`` — 2-byte record
  ``[0x2B][team_index]`` (``msg_expand`` case 0x2B, body dword = second byte).
- Type **1020** (``0x3FC``): ``issue_next_win_message`` ``deliver(..., 0x3FC, team, empty body)``.
  Not in ``msg_compress`` switch; on C2 often wrapped as ``400204`` tag ``0x14`` (type 1020);
  team index is in the deliver arg (1-based team slot), not in the fixed ladder template bytes.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .wa_binary_depack import depack_wa_block
from .wa_gamenet_containers import (
    MSG_SAVE_401E_END,
    MSG_SAVE_401E_WIN,
    extract_msg_save_stream,
    msg_save_magic_label,
)
from .wa_lz77 import lz77_decompress_maybe

TASK_TYPE_OFFSET = 1000
TASK_MSG_SURRENDER = 1043
TASK_MSG_WIN_COMMENTARY = 1020
WIRE_TAG_SURRENDER = TASK_MSG_SURRENDER - TASK_TYPE_OFFSET  # 0x2B
WIRE_TAG_WIN = TASK_MSG_WIN_COMMENTARY - TASK_TYPE_OFFSET  # 0x14

C2_WRAPPER_400204 = b"\x40\x02\x04"
C2_WRAPPER_400204_SUFFIX = b"\x03\x0c\x1e"

# RBot / host occupies lobby slot 0; WA ``team_arena`` uses the same index for the host team.
HOST_LOBBY_SLOT = 0

# msg_expand cases that consume 2 bytes: [tag][byte0 -> body dword]
_TWO_BYTE_RECORD_TAGS = frozenset(
    {
        0x1E,
        0x1F,
        0x20,
        0x21,
        0x24,
        0x25,
        0x26,
        0x27,
        0x2B,
        0x2C,
        0x2D,
        0x2E,
        0x43,
    }
)

# msg_expand 0x16 with param_6 < 0: 2 bytes, body dword = second byte
_TAG_0x16_SHORT = 0x16

# msg_expand 0x12 / 0x13: 3 bytes
_THREE_BYTE_TAGS = frozenset({0x12, 0x13})


@dataclass(frozen=True, slots=True)
class ParsedTaskMessage:
    task_type: int
    wire_tag: int
    team_index: int | None
    offset: int
    raw: bytes


def task_type_from_wire_tag(tag: int) -> int:
    return (tag & 0xFF) + TASK_TYPE_OFFSET


def _expand_consume(data: bytes, pos: int) -> int:
    """Return record length at ``pos``, or 0 if unknown / truncated."""
    if pos >= len(data):
        return 0
    tag = data[pos]
    remaining = len(data) - pos
    if tag in _TWO_BYTE_RECORD_TAGS:
        return 2 if remaining >= 2 else 0
    if tag in _THREE_BYTE_TAGS:
        return 3 if remaining >= 3 else 0
    if tag == _TAG_0x16_SHORT:
        return 2 if remaining >= 2 else 0
    if tag == 0x0C and remaining >= 6:
        # msg_expand case 0x0C: 6-byte record
        return 6
    if tag == 0x09 and remaining >= 5:
        return 5
    if tag == 0x06:
        return 2 if remaining >= 2 else 0
    return 0


def _team_from_record(tag: int, payload: bytes) -> int | None:
    if tag in _TWO_BYTE_RECORD_TAGS | {_TAG_0x16_SHORT} and payload:
        return payload[0]
    if tag in _THREE_BYTE_TAGS and payload:
        return payload[0]
    return None


def walk_task_stream(data: bytes, *, start: int = 0) -> list[ParsedTaskMessage]:
    out: list[ParsedTaskMessage] = []
    pos = start
    while pos < len(data):
        consumed = _expand_consume(data, pos)
        if consumed <= 0:
            break
        tag = data[pos]
        payload = data[pos + 1 : pos + consumed]
        out.append(
            ParsedTaskMessage(
                task_type=task_type_from_wire_tag(tag),
                wire_tag=tag,
                team_index=_team_from_record(tag, payload),
                offset=pos,
                raw=data[pos : pos + consumed],
            )
        )
        pos += consumed
    return out


def _best_walk(data: bytes) -> list[ParsedTaskMessage]:
    """Try aligned walks from several offsets; prefer longest parse with result types."""
    if not data:
        return []
    best: list[ParsedTaskMessage] = []
    best_score = -1
    limit = min(len(data), 64)
    for start in range(limit):
        walked = walk_task_stream(data, start=start)
        if not walked:
            continue
        score = len(walked)
        for msg in walked:
            if msg.task_type in (TASK_MSG_SURRENDER, TASK_MSG_WIN_COMMENTARY):
                score += 10
        if score > best_score:
            best_score = score
            best = walked
    return best


def _regions_from_c2_body(body: bytes) -> list[bytes]:
    """Extract byte regions that may contain serialized task records."""
    regions: list[bytes] = []
    if not body:
        return regions

    regions.append(body)

    # GameNet/WS payload can be directly LZ77-compressed (GameNet__update_incoming_1 calls
    # LZ77Decompress_Maybe over the payload buffer). Try a small set of aligned starts,
    # and also handle the case where the buffer still includes the 4-byte WS header.
    candidates: list[bytes] = [body]
    if len(body) >= 4:
        cmd = (body[0] >> 4) & 0xF
        peer_idx = body[0] & 0xF
        if cmd <= 3 and peer_idx <= 7:
            candidates.append(body[4:])
    for cand in candidates:
        if len(cand) < 6:
            continue
        for start in range(0, min(24, len(cand) - 1)):
            # Endgame frames can carry larger task payloads; allow a bigger window.
            depacked = lz77_decompress_maybe(cand[start:], max_decompressed=0x2000)
            if not depacked or len(depacked) < 8:
                continue
            if depacked.count(0) > (len(depacked) * 0.8):
                continue
            regions.append(depacked)
            break

    # GameNet application packets sometimes embed an LZ77-compressed task stream.
    # These appear as 0x40/0xC0 0x70..0x73 blocks in captured channel-2 bodies.
    # The exact framing differs across contexts; probe several plausible starts.
    if len(body) > 8:
        for i in range(len(body) - 2):
            b0 = body[i]
            b1 = body[i + 1]
            if b0 not in (0x40, 0xC0):
                continue
            if b1 < 0x70 or b1 > 0x73:
                continue
            # In live captures the `40/ c0 70..73` marker is often inside a larger
            # container; the LZ77 payload may begin a few bytes before/after it.
            # Try a small window around the marker.
            for start in range(max(0, i - 24), min(len(body), i + 32)):
                if start >= len(body):
                    continue
                depacked = lz77_decompress_maybe(body[start:], max_decompressed=0x2000)
                if not depacked or len(depacked) < 8:
                    continue
                if depacked.count(0) > (len(depacked) * 0.8):
                    continue
                regions.append(depacked)
                # Don't break: multiple embedded blocks can exist in one body.
                # Keep scanning for more candidate streams.

    # Some bodies embed a depack-compressed task stream blob. The exact start offset
    # isn't stable across contexts, so probe a small window and accept the first
    # plausible depack output.
    if len(body) > 32:
        for start in range(0, 24):
            depacked = depack_wa_block(body[start:])
            if not depacked or len(depacked) < 8:
                continue
            # Heuristic: task stream should contain small tags and not be mostly zero.
            if depacked.count(0) > (len(depacked) * 0.7):
                continue
            regions.append(depacked)
            break

    # msg_save / GameNet containers (401e0202, 5c1f0202, 44020001, …)
    regions.extend(extract_msg_save_stream(body))

    # Each 400204 wrapper payload (after optional 03 0c 1e suffix)
    idx = 0
    while idx + 7 <= len(body):
        pos = body.find(C2_WRAPPER_400204, idx)
        if pos < 0:
            break
        payload_start = pos + 4
        if body.startswith(C2_WRAPPER_400204_SUFFIX, payload_start):
            payload_start += len(C2_WRAPPER_400204_SUFFIX)
        regions.append(body[payload_start:])
        idx = pos + 4

    return regions


def scan_c2_body_for_task_messages(body: bytes) -> list[ParsedTaskMessage]:
    """Collect task messages from all plausible regions in one channel-2 body."""
    found: list[ParsedTaskMessage] = []
    seen: set[tuple[int, int, bytes]] = set()
    for region in _regions_from_c2_body(body):
        for msg in _best_walk(region):
            if (
                msg.task_type == TASK_MSG_SURRENDER
                and msg.team_index is not None
                and msg.team_index > 8
            ):
                continue
            key = (msg.task_type, msg.team_index or -1, msg.raw)
            if key in seen:
                continue
            seen.add(key)
            found.append(msg)
    # Also scan for isolated 2-byte 0x2B records (msg_compress layout)
    for i in range(len(body) - 1):
        if body[i] != WIRE_TAG_SURRENDER:
            continue
        team = body[i + 1]
        if team > 8:
            continue
        raw = body[i : i + 2]
        key = (TASK_MSG_SURRENDER, team, raw)
        if key in seen:
            continue
        seen.add(key)
        found.append(
            ParsedTaskMessage(
                task_type=TASK_MSG_SURRENDER,
                wire_tag=WIRE_TAG_SURRENDER,
                team_index=team,
                offset=i,
                raw=raw,
            )
        )
    return found


def parse_c2_400204_wrappers(body: bytes) -> list[tuple[int, bytes]]:
    """Return ``(TaskMessageType, payload)`` for each ``40 02 04 <tag> …`` record in a C2 body."""
    out: list[tuple[int, bytes]] = []
    idx = 0
    while idx + 7 <= len(body):
        pos = body.find(C2_WRAPPER_400204, idx)
        if pos < 0:
            break
        if pos + 7 > len(body):
            break
        tag = body[pos + 3]
        msg_type = task_type_from_wire_tag(tag)
        payload_start = pos + 4
        if body.startswith(C2_WRAPPER_400204_SUFFIX, payload_start):
            payload_start += len(C2_WRAPPER_400204_SUFFIX)
        out.append((msg_type, body[payload_start:]))
        idx = pos + 4
    return out


def map_team_index_to_slot(index: int, valid_slots: set[int]) -> int | None:
    # Some msg_expand paths carry the team index with flag bits set (commonly 0x80).
    if index >= 0x80:
        index = index & 0x0F
    if index in valid_slots:
        return index
    if index + 1 in valid_slots:
        return index + 1
    if index - 1 in valid_slots:
        return index - 1
    return None


def wire_win_index_to_slot(index: int, valid_slots: set[int]) -> int | None:
    """Map a task-1020 team byte to a lobby slot when the host is slot 0.

  ``valid_slots`` is usually human teams only (e.g. ``{1, 2}``). Many ``0c 14`` records
  use a **human-only 0-based** index (0 → first human / slot 1, 1 → second / slot 2),
  not the lobby slot number and not ``index + 1`` blindly.
    """
    if index >= 0x80:
        index = index & 0x0F
    human_slots = sorted(valid_slots)
    if 0 <= index < len(human_slots):
        return human_slots[index]
    if index in valid_slots:
        return index
    return map_team_index_to_slot(index, valid_slots)


def _scan_framed_tag(body: bytes, wire_tag: int) -> list[tuple[int, int]]:
    """Return (offset, team_index) for ``0c <tag> <idx>`` (401e / msg_save framing)."""
    hits: list[tuple[int, int]] = []
    for i in range(len(body) - 2):
        if body[i] != 0x0C or body[i + 1] != wire_tag:
            continue
        team_index = body[i + 2]
        if team_index > 8:
            # ``0c <marker> <team> 0c 14 <junk>`` — team is before ``0c 14``, not after.
            # Elite uses marker 0xb4; rank 401e uses 0xc0/0xcc (20260601T073140Z-rank).
            if (
                wire_tag == WIRE_TAG_WIN
                and i >= 3
                and body[i - 3] == 0x0C
                and body[i - 1] <= 8
            ):
                team_index = body[i - 1]
            else:
                continue
        hits.append((i, team_index))
    return hits



def parse_win_announcements(body: bytes) -> list[tuple[int, int]]:
    """Type 1020 (``issue_next_win_message``) on the wire.

    Forms seen in captures:
    - ``0c 14 <team_index>`` inside ``401e`` / msg_save containers
    - ``40 02 04 14`` fanfare ladder — team is only reliable via inner ``0c 14`` (the byte
      after ``03 0c 1e`` in captures is a fixed template, not the winner slot).
    """
    hits = _scan_framed_tag(body, WIRE_TAG_WIN)
    for msg_type, payload in parse_c2_400204_wrappers(body):
        if msg_type != TASK_MSG_WIN_COMMENTARY:
            continue
        for off, idx in _scan_framed_tag(payload, WIRE_TAG_WIN):
            if (off, idx) not in hits:
                hits.append((off, idx))
    return hits


def parse_surrender_announcements(body: bytes) -> list[tuple[int, int]]:
    """Type 1043 (``surrender_team``) on the wire.

    Forms:
    - ``0c 2b <team_index>`` in msg_save
    - ``2b <team_index>`` via ``msg_expand`` (sometimes ``0x80 | slot``)
    - ``40 02 04 2b …`` wrapper (rare)
    """
    hits = _scan_framed_tag(body, WIRE_TAG_SURRENDER)
    seen = {h[0] for h in hits}
    for msg in scan_c2_body_for_task_messages(body):
        if msg.task_type != TASK_MSG_SURRENDER or msg.team_index is None:
            continue
        if msg.offset not in seen:
            hits.append((msg.offset, msg.team_index))
            seen.add(msg.offset)
    for msg_type, payload in parse_c2_400204_wrappers(body):
        if msg_type != TASK_MSG_SURRENDER or not payload:
            continue
        hits.append((0, payload[0]))
    return hits




def scan_msg_save_frames(bodies: list[bytes]) -> list[dict[str, object]]:
    """Per-body summary for ``401e*`` msg_save containers (rank endgame RE)."""
    frames: list[dict[str, object]] = []
    for body in bodies:
        magic = msg_save_magic_label(body)
        if magic not in ("401e0202", "401e0102"):
            continue
        inner = b"".join(extract_msg_save_stream(body))
        scan = inner if inner else body[4:]
        frames.append(
            {
                "magic": magic,
                "has_0c14": b"\x0c\x14" in scan,
                "has_0c2b": b"\x0c\x2b" in scan,
                "has_0c62": b"\x0c\x62" in scan,
                "len": len(body),
            }
        )
    return frames


def summarize_wire_re_gap(bodies: list[bytes]) -> dict[str, object]:
    """Corpus flags for capture when strict decode fails (no heuristics)."""
    has_0c14 = False
    has_0c2b = False
    has_0c62 = False
    has_401e0202 = False
    has_401e0102 = False
    has_5c1f = False
    has_4070 = False
    sample_prefixes: list[str] = []
    seen_prefix: set[str] = set()
    win_hits_count = 0
    sur_hits_count = 0

    for body in bodies:
        if not body:
            continue
        if b"\x0c\x14" in body:
            has_0c14 = True
        if b"\x0c\x2b" in body:
            has_0c2b = True
        if b"\x0c\x62" in body:
            has_0c62 = True
        if body.startswith(MSG_SAVE_401E_WIN):
            has_401e0202 = True
        if body.startswith(MSG_SAVE_401E_END):
            has_401e0102 = True
        if b"\x5c\x1f\x02\x02" in body:
            has_5c1f = True
        for i in range(len(body) - 1):
            b0, b1 = body[i], body[i + 1]
            if b0 in (0x40, 0xC0) and 0x70 <= b1 <= 0x73:
                has_4070 = True
                break

        if len(body) >= 4:
            pfx = body[:4].hex()
            if pfx not in seen_prefix and len(sample_prefixes) < 6:
                seen_prefix.add(pfx)
                sample_prefixes.append(pfx)

        win_hits_count += len(parse_win_announcements(body))
        sur_hits_count += len(parse_surrender_announcements(body))

    msg_save_frames = scan_msg_save_frames(bodies)
    return {
        "has_0c14": has_0c14,
        "has_0c2b": has_0c2b,
        "has_0c62": has_0c62,
        "has_401e": has_401e0202 or has_401e0102,
        "has_401e0202": has_401e0202,
        "has_401e0102": has_401e0102,
        "has_5c1f": has_5c1f,
        "has_4070": has_4070,
        "n_bodies": len(bodies),
        "sample_prefixes": sample_prefixes,
        "win_hits_count": win_hits_count,
        "sur_hits_count": sur_hits_count,
        "msg_save_frames": msg_save_frames,
    }

@dataclass(frozen=True, slots=True)
class AnnouncedResult:
    winner_slot: int | None
    loser_slot: int | None
    reason: str
    details: dict[str, object]


def announced_result_from_bodies(
    bodies: list[bytes],
    valid_slots: set[int],
) -> AnnouncedResult | None:
    """Parse task-1020 / task-1043 announcements from C2 bodies (strict decode only)."""
    win_hits: list[tuple[int, int, bytes]] = []
    surrender_hits: list[tuple[int, int, bytes]] = []
    for body in bodies:
        for off, idx in parse_win_announcements(body):
            win_hits.append((off, idx, body))
        for off, idx in parse_surrender_announcements(body):
            if map_team_index_to_slot(idx, valid_slots) is not None:
                surrender_hits.append((off, idx, body))

    winner_slot: int | None = None
    loser_slot: int | None = None
    reason = ""
    details: dict[str, object] = {}

    if win_hits:
        _off, idx, body = win_hits[-1]
        slot = wire_win_index_to_slot(idx, valid_slots)
        if slot is not None:
            winner_slot = slot
            reason = "task-1020"
            details["win_hits"] = [(off, idx, body.hex()) for off, idx, body in win_hits[-3:]]

    if surrender_hits:
        _off, idx, body = surrender_hits[-1]
        slot = map_team_index_to_slot(idx, valid_slots)
        if slot is not None:
            loser_slot = slot
            if not reason:
                reason = "task-1043"
            details["surrender_hits"] = [
                (off, idx, body.hex()) for off, idx, body in surrender_hits[-3:]
            ]

    if winner_slot is not None and loser_slot is None and len(valid_slots) == 2:
        others = [s for s in valid_slots if s != winner_slot]
        if len(others) == 1:
            loser_slot = others[0]

    if winner_slot is None and loser_slot is not None:
        survivors = [s for s in valid_slots if s != loser_slot]
        if len(survivors) == 1:
            winner_slot = survivors[0]
            if not reason:
                reason = "task-1043"

    # Multi-team elimination: if we see multiple distinct 1043 (surrender_team) losers,
    # infer the sole remaining slot even if 1020 never shows up on wire.
    if winner_slot is None and surrender_hits and len(valid_slots) >= 2:
        losers: set[int] = set()
        for _off, idx, _body in surrender_hits:
            slot = map_team_index_to_slot(idx, valid_slots)
            if slot is not None:
                losers.add(slot)
        survivors = [s for s in valid_slots if s not in losers]
        if len(survivors) == 1:
            winner_slot = survivors[0]
            if not reason:
                reason = "task-1043-multi"
            details["surrender_losers"] = sorted(losers)

    if winner_slot is not None:
        return AnnouncedResult(
            winner_slot=winner_slot,
            loser_slot=loser_slot,
            reason=reason,
            details=details,
        )
    return None


def count_400204_ladder_frames(body: bytes) -> int:
    """Count non-surrender 400204 wrappers (msg_save fanfare ladder steps)."""
    count = 0
    for msg_type, _payload in parse_c2_400204_wrappers(body):
        if msg_type != TASK_MSG_SURRENDER:
            count += 1
    return count


@dataclass
class EndgameTracker:
    """OpenWA-style endgame state inferred from task messages on the wire.

    Mirrors the in-client rule: teams eliminated via ``1043`` (surrender / flush),
    winner from explicit ``1020`` or the sole remaining team slot.
    """

    valid_slots: set[int]
    eliminated_slots: set[int] = field(default_factory=set)
    _explicit_winner_slot: int | None = None

    def observe_body(self, body: bytes) -> None:
        """Ingest one channel-2 body (call for every frame while gameplay is active)."""
        for _off, idx in parse_win_announcements(body):
            slot = wire_win_index_to_slot(idx, self.valid_slots)
            if slot is not None:
                self._explicit_winner_slot = slot
        for _off, idx in parse_surrender_announcements(body):
            slot = map_team_index_to_slot(idx, self.valid_slots)
            if slot is not None:
                self.eliminated_slots.add(slot)

    def announced_result(self) -> AnnouncedResult | None:
        winner_slot = self._explicit_winner_slot
        loser_slot: int | None = None
        reason = ""

        if winner_slot is not None:
            reason = "task-1020"
        elif self.eliminated_slots and len(self.valid_slots) >= 2:
            survivors = [s for s in self.valid_slots if s not in self.eliminated_slots]
            if len(survivors) == 1:
                winner_slot = survivors[0]
                reason = "task-1043-tracker"
            elif len(survivors) == 0 and len(self.eliminated_slots) >= 2:
                # All teams eliminated (draw) — no winner.
                return None

        if winner_slot is None:
            return None

        losers = self.eliminated_slots
        if len(losers) == 1:
            loser_slot = next(iter(losers))
        elif winner_slot in self.valid_slots:
            others = [s for s in self.valid_slots if s != winner_slot]
            if len(others) == 1:
                loser_slot = others[0]

        return AnnouncedResult(
            winner_slot=winner_slot,
            loser_slot=loser_slot,
            reason=reason,
            details={
                "eliminated_slots": sorted(self.eliminated_slots),
                "explicit_winner": self._explicit_winner_slot,
            },
        )
