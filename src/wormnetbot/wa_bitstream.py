"""
``BitStreamRead::get_bit`` / ``get_bits`` / ``get_byte`` (32-bit WA build).

**Implemented model:** a single 8-bit hold and a count of how many bits remain in it
(MSB shifted out first, then ``get_byte`` refills). This matches ``get_bits(8)`` on one
raw byte and, together with ``depack_block`` in ``wa_binary_depack``, successfully
decompresses **real** channel-2 bodies from this project’s captures.

The Hex-Rays listing with ``this+0x10`` / ``+0x11`` and a different update order was
tried; it still passed a one-byte ``0x5A`` self-test but **desynced** on long
``depack`` runs (literal ``get_byte`` over-read). Use this version until a
debugger proves the exact C++ state machine for your binary.
"""

from __future__ import annotations


class WABitStreamRead:
    __slots__ = ("_data", "_c", "_bit_hold", "_bits_in_hold")

    def __init__(self, data: bytes) -> None:
        self._data = bytes(data)
        self._c = 0
        self._bit_hold = 0
        self._bits_in_hold = 0

    def get_byte(self) -> int:
        if self._c >= len(self._data):
            raise IndexError("BitStreamRead::get_byte past end")
        b = self._data[self._c]
        self._c += 1
        return b & 0xFF

    def get_bit(self) -> int:
        if self._bits_in_hold == 0:
            self._bit_hold = self.get_byte()
            self._bits_in_hold = 8
        bit = (self._bit_hold >> 7) & 1
        self._bit_hold = (self._bit_hold << 1) & 0xFF
        self._bits_in_hold -= 1
        return bit

    def get_bits(self, n: int) -> int:
        if n <= 0 or n > 32:
            raise ValueError("bad bit count")
        v = 0
        for _ in range(n):
            v = (v * 2) + self.get_bit()
        return v


if __name__ == "__main__":
    s = WABitStreamRead(bytes([0x5A]))
    assert s.get_bits(8) == 0x5A
    assert s._c == 1
