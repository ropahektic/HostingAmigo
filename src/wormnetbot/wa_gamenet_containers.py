"""GameNet / msg_save container layouts seen on channel-2 (RE in progress).

Captures:
- ``401e0202`` — winner-side msg_save; inner ``0c14`` = task-1020 team byte (when emitted).
- ``401e0102`` — endgame msg_save without ``0c14`` (same family, other subtype).
- ``5c1f0202`` / ``5c1e0202`` — length-prefixed chunk containers (rank surrender).
- ``44020001`` — Elite League; framed ``0c2b`` / ``0c14``.
"""

from __future__ import annotations

import struct

MSG_SAVE_401E_WIN = b"\x40\x1e\x02\x02"
MSG_SAVE_401E_END = b"\x40\x1e\x01\x02"

MSG_SAVE_MAGICS = (
    MSG_SAVE_401E_WIN,
    MSG_SAVE_401E_END,
    b"\x5c\x1f\x02\x02",
    b"\x5c\x1e\x02\x02",
    b"\x64\x1e\x02\x02",
    b"\x44\x02\x00\x01",
    b"\x44\x02\x00\x02",
)


def extract_length_chunk_payloads(body: bytes) -> list[bytes]:
    """Return inner payloads from ``<magic> [u16 len][data]…`` containers."""
    out: list[bytes] = []
    for magic in MSG_SAVE_MAGICS:
        if not body.startswith(magic):
            continue
        off = len(magic)
        while off + 2 <= len(body):
            (ln,) = struct.unpack_from("<H", body, off)
            off += 2
            if ln == 0 or off + ln > len(body):
                break
            out.append(body[off : off + ln])
            off += ln
    return out


def extract_msg_save_stream(body: bytes) -> list[bytes]:
    """All byte regions to scan for ``msg_expand`` task records inside a C2 body."""
    regions: list[bytes] = []
    if not body:
        return regions

    chunks = extract_length_chunk_payloads(body)
    if chunks:
        regions.extend(chunks)
        return regions

    for magic in MSG_SAVE_MAGICS:
        if body.startswith(magic) and len(body) > len(magic):
            regions.append(body[len(magic) :])
            break

    return regions


def msg_save_magic_label(body: bytes) -> str | None:
    """Return a short label for the leading msg_save magic, if any."""
    if body.startswith(MSG_SAVE_401E_WIN):
        return "401e0202"
    if body.startswith(MSG_SAVE_401E_END):
        return "401e0102"
    if len(body) >= 4:
        return body[:4].hex()
    return None
