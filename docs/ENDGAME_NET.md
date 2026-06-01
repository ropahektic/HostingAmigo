# Endgame network handshake (RBot)

OpenWA splits match teardown into two layers. RBot must handle both differently.

| Layer | Mechanism | RBot today |
|-------|-----------|------------|
| **Winner** | `team_arena` scan when `hud_status_code ∈ {6, 8}` | OpenWA `rbot_sidecar.rs` → shared JSON; RBot `openwa_winner_sidecar.py` (`WORMNET_OPENWA_WINNER_PATH`) |
| **PLEASE WAIT / lobby return** | `BeginNetworkGameEnd` → GameNet MachineQuit `0x0D`, then C2 ritual | `EndgameNetState` in `endgame_net.py` + relay in `game_host.py` |

## OpenWA `game_state` (in-process)

From `third_party/OpenWA/.../step_frame.rs`:

1. **`NETWORK_END_STARTED` (3)** — `begin_network_game_end`: 12-byte `[0x0D, starting_team_index, 1]` via `GameNet::send_block`.
2. **`NETWORK_END_AWAITING_PEERS` (2)** — peer scores / ready flags; bounded `net_end_countdown`.
3. **`ROUND_ENDING` (4)** — turn-end broadcast `0x75`; C2 fanfare + sentinel exchange.
4. **`EXIT` (5)** — return to front-end.

RBot does **not** inject MachineQuit on GameNet yet (lives above raw C2). It **does** relay C2 faithfully.

## Visible C2 ritual (rank fast-surrender)

Per human peer, typical order:

1. **`5c1f0202…`** — msg_save container burst (surrender path; no bare `0c2b` on wire).
2. **`400204…`** ladder — fanfare / commentary steps from surrendering client.
3. **`400600`** — body `40 06 00` (endgame sentinel).
4. **`c00d…`** — lobby-return prefix (after sentinel).

`EndgameNetState` tracks: `saw_5c1f`, `ladder_400204_frames`, `sent_400600`, `sent_c00d`.

## Relay rules (`game_host.py`)

- **Never** stop C2 relay on first `400600` (strands peer in 10s PLEASE WAIT).
- **Preserve sender frame index** for all endgame-class bodies (no catch-up remap on sentinel/`c00d`).
- **No synthetic** `400600` / `c00d` inject while winner may still be in fanfare (disabled).
- **Strict winner** only from task **1020** / **1043** decode (`EndgameTracker`); rank games often have neither on C2.

## OpenWA arena sidecar

On VM101 (OpenWA build), set:

```text
RBOT_WINNER_SIDECAR_PATH=\\share\wormnet\winner.json
```

On CT104 (RBot), set the same file via:

```text
WORMNET_OPENWA_WINNER_PATH=/mnt/wormnet/winner.json
```

OpenWA writes once per game-over HUD transition (`step_frame` Block A). RBot clears the file on `start_game` and reads it after strict C2 decode fails. Reason: `openwa-arena`.

## Next steps

1. Optional host inject of 12-byte MachineQuit if captures show clients expect it below C2.
2. GameNet LZ77 on `4070` blocks — only if we need winner from relay bytes alone.
