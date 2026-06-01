# Channel-2 `c070` / `4070` GameNet envelope (rank captures)

Mapped from **178** `c070` frames across `captures/*rank*.jsonl` (May 2026) and OpenWA `WS_GameNet__ReceivePacket` (4-byte header + LZ77 **inside** the opaque payload — not at envelope offset 0).

## Magic families

| Byte 0 | Byte 1 | Direction on capture | Count (subtype `0x06`) |
|--------|--------|--------------------|-------------------------|
| `0xC0` | `0x70` | Client → host (`in`) | ~210 |
| `0x40` / `0x44` | `0x70` | Host relay (`out`) | ~255 |

Same layout after byte 0; RBot relay may rewrite `0xC0` ↔ `0x40` (sometimes `0x44` on 22 B masks). **`0x70` is the GameNet transport tag** on channel 2 (not the same as raw TCP `WS_GameNet` scratch).

## Length classes

| Total len | Class | `[3]` | Notes |
|-----------|-------|-------|--------|
| **22** | Host connection mask | `0x02` | Fixed template; RBot `host_mask_gamenet_body()` |
| **64–92** | Per-peer load blob | `0x06` | Session-shared prefix + per-peer tail |
| other | Rare variants | `0x06` / other | Same header discipline |

## Layout: subtype `0x06` (load / gameplay GameNet)

```
Offset   Size   Field
------   ----   -----
0        1      0xC0 or 0x40 (channel direction)
1        1      0x70 (GameNet family)
2        1      peer_byte — session id in high nibble; **low nibble ≠ wormnet wire** in captures (often `0xF`). For relay to a client, use `(peer_byte & 0xF0) | roster_wire` (see `peer_byte_from_capture_template`).
3        1      0x06 — load / game GameNet blob
4        1      game_key — constant per match (`0xb3`, `0xe5`, `0xab`, …)
5        14     session_id — **identical for all peers** in the same match
19       n-20   per_peer_payload — opaque in captures (LZ77 **not** found at offset 0/1; see below)
len-1    1      0x00 — trailing terminator (always present)
```

### Example (`20260601T101316Z-rank`, red vs blue2)

```
c070 4f 06 b3  ea150176308aca64055b4326a031  | 9ef82a4a2427d92b... | 00
     ^peer ^  ^key ^------ session (14) ------^  ^-- per-peer (65 B) --^
```

- Red: 84 B total, payload 65 B from offset 19  
- Blue2: 68 B total, payload 49 B from offset 19  
- **Same** bytes `[3:19]` (`06 b3` + session) for both peers in a match.

## Layout: subtype `0x02` (22 B host mask)

```
c070 01 02 02 95 01 00 00 5e eb 47 3c 31 00 00 00 9d c6 f2 bc 00
^^   ^peer ^  ^--- 18-byte fixed template ----------^
```

| Offset | Value |
|--------|--------|
| 0–1 | `C0 70` |
| 2 | `0x01` (host peer byte) |
| 3 | `0x02` |
| 4–21 | Fixed mask body (capture template in `wa_gamenet_handshake._HOST_MASK_TEMPLATE`) |

No separate 14-byte session block; total size is always **22**.

## Relation to `WS_GameNet` wire packet

Inside WA (OpenWA RE):

1. `WS_GameNet__ReceivePacket` reads **4-byte header** (peer nibble, tag nibble, 24-bit seq) + **LZ77 blob** with **byte 0 = wire seed `0x00`**.
2. That packet is **not** stored raw on channel 2 — it is wrapped in the `c070` envelope above.

Corpus checks (2026-06-01):

- `lz77_decompress_maybe` on `body[0:48]` or `body[19:]` → **no** decode  
- `depack_wa_block` (task/replay compressor) → **no** decode  

So the **per_peer_payload** is still an inner container (likely MsgConnection / BufferObject serialization, possibly encrypted or bit-packed). Next RE step: find where channel-2 `0x70` is emitted in WA and what wraps LZ77.

## RBot usage

| Phase | Action |
|-------|--------|
| LOADING | Relay `c070`/`4070` as-is (PASSIVE); optional host mask `0x02` 22 B |
| ENDGAME | Do **not** invent LZ77 inside `c070` until payload decode works; trigger only at `NETWORK_END_AWAITING_PEERS` |

Parser: `wormnetbot.wa_gamenet_wire.parse_c070_envelope` — validates **626/626** rank `0x70` frames (159 masks + 467 load blobs).

## Probe command

```bash
cd /opt/WormNETBot
PYTHONPATH=src python3 scripts/lz77_corpus_probe.py captures/20260601T101316Z-rank.jsonl
```
