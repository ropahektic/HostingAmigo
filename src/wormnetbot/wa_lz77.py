"""WA GameNet LZ77 — BlockFifo (partial port; see scripts/lz77_corpus_probe.py)."""

from __future__ import annotations


class _BitReader:
    __slots__ = ("data", "limit", "pos", "shift_reg", "bit_out")

    def __init__(self, data: bytes, *, start_pos: int = 1) -> None:
        self.data = data
        self.limit = len(data)
        self.pos = 0
        self.shift_reg = 1
        self.bit_out = 0
        if data:
            b0 = data[0]
            self.bit_out = (b0 >> 7) & 1
            self.shift_reg = ((b0 << 1) & 0xFF) | 1
            self.pos = start_pos

    def _refill(self) -> None:
        self.pos += 1
        if self.pos >= self.limit:
            raise IndexError("out of input")
        b = self.data[self.pos]
        self.bit_out = (b >> 7) & 1
        self.shift_reg = ((b << 1) & 0xFF) | 1

    def get_bit(self) -> int:
        bit = self.bit_out & 1
        self.bit_out = (self.shift_reg >> 7) & 1
        self.shift_reg = (self.shift_reg << 1) & 0xFF
        if self.shift_reg == 0:
            self._refill()
        return bit

    def consume_bits(self, n: int) -> int:
        v = 0
        for _ in range(n):
            v = self.get_bit() + (v * 2)
        return v

    def read_literals(self, n: int) -> bytes:
        start = self.pos
        end = start + n
        if end > self.limit:
            raise IndexError("literal overrun")
        chunk = self.data[start:end]
        self.pos = end
        if self.pos < self.limit:
            b = self.data[self.pos]
            self.bit_out = (b >> 7) & 1
            self.shift_reg = ((b << 1) & 0xFF) | 1
        else:
            self.bit_out = 1
            self.shift_reg = 1
        return chunk


def lz77_decompress_maybe(
    compressed: bytes,
    *,
    max_decompressed: int = 0x400,
    seed_from_first_byte: bool = True,
    start_pos: int = 1,
) -> bytes | None:
    if not compressed:
        return b""
    if not seed_from_first_byte:
        return None
    r = _BitReader(compressed, start_pos=start_pos)
    out = bytearray()
    try:
        while True:
            if r.get_bit() != 0:
                len_code = r.consume_bits(4)
                if len_code < 1:
                    dist = r.consume_bits(8)
                    if dist == 0:
                        return bytes(out)
                    length = r.consume_bits(8) + 0x12
                else:
                    length = len_code + 2
                    dist = r.consume_bits(8) + 1
                if dist <= 0 or dist > len(out) or len(out) + length > max_decompressed:
                    return None
                src = len(out) - dist
                for _ in range(length):
                    out.append(out[src])
                    src += 1
            else:
                length = r.consume_bits(8) + 1
                if length <= 0 or len(out) + length > max_decompressed:
                    return None
                out.extend(r.read_literals(length))
    except IndexError:
        return None


def lz77_decompress_try_offsets(
    blob: bytes,
    *,
    max_decompressed: int = 0x400,
    max_offset: int = 48,
) -> list[tuple[int, int, bytes]]:
    hits: list[tuple[int, int, bytes]] = []
    for off in range(min(max_offset, len(blob))):
        for start_pos in (0, 1):
            dec = lz77_decompress_maybe(
                blob[off:],
                max_decompressed=max_decompressed,
                start_pos=start_pos,
            )
            if dec and len(dec) >= 4:
                hits.append((off, start_pos, dec))
    return hits


class _BitWriter:
    __slots__ = ("buf", "byte_i", "shift")

    def __init__(self, buf: bytearray) -> None:
        self.buf = buf
        self.byte_i = 1
        self.shift = 0

    def _ensure(self) -> None:
        while self.byte_i >= len(self.buf):
            self.buf.append(0)

    def advance(self) -> None:
        self.shift += 1
        if self.shift == 8:
            self.byte_i += 1
            self.shift = 0
            self._ensure()

    def emit_one(self) -> None:
        self._ensure()
        self.buf[self.byte_i] |= 0x80 >> self.shift
        self.advance()

    def put(self, n: int, val: int) -> None:
        for i in range(n - 1, -1, -1):
            if (val >> i) & 1:
                self.emit_one()
            else:
                self.advance()


def lz77_compress_maybe(data: bytes) -> bytes:
    buf = bytearray([0])
    bits = _BitWriter(buf)
    lit = bytearray()
    i, n = 0, len(data)

    def flush_literals() -> None:
        nonlocal lit
        if not lit:
            return
        bits.advance()
        bits.put(8, len(lit) - 1)
        start = bits.byte_i
        bits.shift = 0
        for j, b in enumerate(lit):
            idx = start + j
            while idx >= len(buf):
                buf.append(0)
            buf[idx] = b
        bits.byte_i = start + len(lit)
        lit.clear()

    while i < n:
        best_len, best_dist = 0, 0
        for j in range(max(0, i - 0xFF), i):
            ln = 0
            while i + ln < n and ln < 0x111 and data[j + ln] == data[i + ln]:
                ln += 1
            if ln >= 3 and ln > best_len:
                best_len, best_dist = ln, i - j
        if best_len >= 3:
            flush_literals()
            bits.emit_one()
            if best_len < 0x12:
                bits.put(4, best_len - 2)
                bits.put(8, best_dist - 1)
            else:
                bits.put(4, 0)
                bits.put(8, best_dist)
                bits.put(8, best_len - 0x12)
            i += best_len
        else:
            lit.append(data[i])
            if len(lit) > 0xFF:
                flush_literals()
            i += 1
    flush_literals()
    bits.emit_one()
    bits.put(4, 0)
    bits.put(8, 0)
    if bits.shift:
        bits.byte_i += 1
    end = bits.byte_i + 1
    buf[0] = 0
    return bytes(buf[: max(1, end)])


def _selftest() -> None:
    c = b"\x0d"
    comp = lz77_compress_maybe(c)
    dec = lz77_decompress_maybe(comp)
    assert dec == c, (comp.hex(), dec)


if __name__ == "__main__":
    _selftest()
    print("ok")
