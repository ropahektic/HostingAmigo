# PLEASE WAIT first — plan (2026-06-01)

WA shows **"PLEASE WAIT %d SEC"** while `GameRuntime__OnNetworkEndAwaitPeers` waits for peers to finish **network end** (`BeginNetworkGameEnd` → `GameNet__send_block` with **MachineQuit `0x0D`**). RBot logs this as **~13s sentinel→`c00d`** when the handshake falls back.

## Two layers (do not mix them)

| Layer | What WA does | On rank captures (fast surrender) |
|-------|----------------|-----------------------------------|
| **GameNet** | 12-byte staging `[0x0D, team, 1]` via `GameNet__send_block` | **Usually no `70xx` on ch2 during endgame** |
| **C2 ritual** | `5c1f` → `400204` ladder → `400600` → `c00d` | Always present; RBot already relays |

**Conclusion:** Fixing PLEASE WAIT is **not** “finish `c070` subtype `0x06` LZ77 first.” That was for synthetic MachineQuit assist — wrong target for rank teardown. Most games never show `0x06` after `400600`.

## What captures show

- Typical endgame ch2: `4002`, `401f`, `5c1f`, `400600`, `c00d` — **no** `c070`/`4070`.
- One session (`20260601T100852Z-rank`): host **OUT** burst of **22 B** `c070` subtype **`0x02`** (host mask), not `0x06` load blobs.
- `GameNet__update_incoming_1`: recv → LZ77 decompress → `GameNet__update_application` (inner path is **inside** WA, may not appear as naked `70xx` at end).

## RBot gaps today

1. **`_gamenet_host_fanout` is never called** — OpenWA star topology: clients send GameNet to peer 0; host must fan out. Code exists in `game_host.py` but is dead.
2. **`_endgame_gamenet_kick` is a no-op** — only logs; disabled after mid-game desync from wrong trigger / wrong blob.
3. **`_relay_gamenet_burst` exists but is never called** — should replay recent `70xx` at `NETWORK_END_AWAITING_PEERS`.
4. **Host mask loop disabled** — `_start_host_gamenet_mask_loop` returns immediately (was “invalid-data spam”).

Relay rules that **are** correct: don’t stop on first `400600`; preserve endgame frame indices; no synthetic `400600`/`c00d`.

## Recommended order (PLEASE WAIT only)

### Phase A — Relay / host topology

1. **Star fan-out only during load** (`not loading_phase_complete`). After load, **peer relay only** — host wire-0 `c070` at endgame caused `invalid data received from Rbot` + index jumps on PLEASE WAIT.
2. **No host inject at net-end** — mask burst and replay via fan-out disabled (same symptoms).
3. **Verify** `game_c2_relay=gameplay` and relay until `EndgamePhase.COMPLETE`.
4. **Measure:** `please_wait_s` in capture / journal.

### Phase B — Observe what WA actually sends (1 RE session)

1. VM101: Frida / OpenWA log on `GameNet__send_block` at surrender (≥2 turns).
2. Correlate with CT104 capture: does MachineQuit appear as **`4070`/`c070`**, inside **`401f`/`4002`**, or only on TCP not tagged `70xx`?
3. Update this doc with the real wire shape.

### Phase C — Codec shim (only if Phase A+B prove host must inject)

Port from Ghidra only what `send_block` emits, wrapped in the **observed** envelope (may be `0x02` mask, not `0x06`).

**Do not re-enable** blind `build_host_machine_quit_c070()` until Phase B roundtrips on corpus.

## Success criteria

- Both humans return to lobby without long PLEASE WAIT.
- Logs: no `PLEASE WAIT fallback likely` (or &lt;8s).
- No mid-match `ENDGAME` / GameNet assist lines.

## Test protocol

- **≥2 turns**, then ESC surrender (not first-turn).
- `journalctl -u wormnetbot -f | grep -E 'PLEASE WAIT|NETWORK_END|GameNet|assist'`

## References

- `Findings.md` — `BeginNetworkGameEnd` @ `0x536270`, MachineQuit `0x0D`
- `docs/ENDGAME_NET.md` — C2 ritual vs GameNet
- `docs/C070_LAYOUT.md` — envelope map (`0x02` vs `0x06`)
