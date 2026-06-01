"""
``BinaryCompressor::depack_block(uchar *a2, int a3, BitStreamRead *a4)`` from the
symbolized idb; ``a3`` does not appear in the decompiled body — we cap output with
``max_decompressed`` instead. Validate on a (compressed, expected) pair from a
debugger when possible.
"""

from __future__ import annotations

import logging
from typing import final

from .wa_bitstream import WABitStreamRead

LOGGER = logging.getLogger(__name__)


def _sext4(v: int) -> int:
    v &= 0xF
    if v & 0x8:
        return v - 16
    return v


def _sext8(v: int) -> int:
    v &= 0xFF
    if v & 0x80:
        return v - 256
    return v


@final
def depack_block(
    bitstream: WABitStreamRead,
    *,
    max_decompressed: int = 0x10_0000,
) -> bytes:
    """
    Decompress using one ``WABitStreamRead`` (shared bit + byte cursor like the C++ object).
    """
    a2: bytearray = bytearray()
    n = 0  # v13

    def _max_ok() -> bool:
        return n < max_decompressed

    def out_byte(b: int) -> None:
        nonlocal n
        if not _max_ok():
            raise IndexError("depack_block output cap")
        a2.append(b & 0xFF)
        n += 1

    def out_copy_back(distance: int) -> None:
        nonlocal n
        if distance <= 0 or n < distance:
            raise ValueError("invalid back-reference")
        if not _max_ok():
            raise IndexError("depack_block output cap")
        a2.append(a2[n - distance] & 0xFF)
        n += 1

    # depack_block body (Hex-Rays)
    while True:
        while True:
            while not bitstream.get_bit():
                bits = bitstream.get_bits(8)
                if (bits & 0xFF) != 0xFF:
                    # do { a2[v13++] = get_byte(); v6 = bits-- == 0; } while (!v6);
                    while True:
                        out_byte(bitstream.get_byte())
                        t = bits
                        bits -= 1
                        if t == 0:
                            break

            v12 = _sext4(bitstream.get_bits(4))
            if v12 + 2 <= 2:
                break
            v8 = bitstream.get_bits(8) + 1
            v9 = v12 + 1
            if v12 != -2:
                while True:
                    out_copy_back(v8)
                    t = v9
                    v9 -= 1
                    if t == 0:
                        break

        v10 = bitstream.get_bits(8)
        if not v10:
            break
        v4 = bitstream.get_bits(8)
        v5 = v4 + 17
        if _sext8(v4) != -18:
            while True:
                out_copy_back(v10)
                t = v5
                v5 -= 1
                if t == 0:
                    break

    return bytes(a2)


@final
def depack_wa_block(compressed: bytes, *, max_decompressed: int = 0x10_0000) -> bytes | None:
    """Convenience: one compressed blob, one ``WABitStreamRead``. ``None`` on error."""
    if not compressed:
        return b""
    try:
        return depack_block(
            WABitStreamRead(compressed),
            max_decompressed=max_decompressed,
        )
    except (IndexError, ValueError) as e:
        LOGGER.debug("depack_wa_block failed: %s", e)
        return None
