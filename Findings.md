# Findings

This document records the winner-detection work completed after the initial open-source release, starting from the moment we began using a special Worms Armageddon build with symbols and ending with successful live winner parsing from WA game packets inside `Rbot`.

## Goal

The goal was to make `Rbot` determine the winner of a hosted WA game automatically from live network traffic, and to attribute that win to the correct team and player without manual input from users.

The important constraint was that we did not want a made-up heuristic if WA itself already knew the answer. The target became: follow WA's own endgame logic as closely as possible, then identify the network-visible signals that appear when WA reaches that decision.

## Starting point

At the start of this work:

- the bot could already host playable games and capture channel-2 traffic;
- the original winner detector in `src/wormnetbot/game_host.py` was heuristic and brittle;
- the question was still open whether WA serialized a dedicated "winner packet" or whether the winner only existed as local game state.

## What changed once we had the symbolized WA build

The symbolized WA build made it possible to stop guessing and inspect real function names and call flow inside the game binary.

The key functions we traced were:

- `issue_next_win_message__13Task_TurnGameRi`
- `comment_public__8GameTaskPPc11DisplayFontPc`
- `surrender_team__13Task_TurnGamei`
- `flush_surrendered_teams__13Task_TurnGame`
- `check_for_survival_deaths__13Task_TurnGame`
- `check_for_vital_deaths__13Task_TurnGame`
- `game_is_over__13Task_TurnGame`
- `set_playing__12GameDatabaseii`
- `get_playing__12GameDatabasei`

That gave us two crucial answers:

1. WA does compute the winner locally using team survival / ally-group state.
2. The obvious local winner announcement path is not itself the packet we need to watch on the network.

## Important binary-level findings

### 1. Winner announcement is local first

`issue_next_win_message__13Task_TurnGameRi` is the function that drives the local winner announcement flow. It feeds winner text into `comment_public`, which is the same general announcer path used for many visible game comments.

This confirmed that the on-screen "Congratulations to %s!" style output is a real endgame signal inside WA, but it did not prove that the same event is serialized in a clean one-packet form for remote observers.

### 2. Team elimination was more useful than the final announcement

Tracing the elimination flow turned out to matter more:

- `check_for_survival_deaths` and `check_for_vital_deaths` decide when teams are effectively out.
- They call `surrender_team__13Task_TurnGamei`.
- `surrender_team` emits a serializable task/message that corresponds to team elimination or surrender.
- `flush_surrendered_teams` is responsible for the public elimination comments.

This shifted the project away from "look for a winner packet" and toward "observe the cluster of endgame packets that WA emits while resolving final team state."

### 3. There is no single clean network winner packet we can rely on

The local winner flow and the network-visible endgame flow are related, but they are not a simple one-to-one mapping where one final packet always names the winner directly.

The practical result was:

- stop searching for a magic winner packet;
- use WA's local logic as the conceptual model;
- learn the repeatable packet patterns that appear when that logic finishes.

## Why the `text strings` dump mattered

The `text strings` file was the bridge between binary symbols and observed in-game behavior.

It let us connect visible announcements and comment-table names, including:

- winner comments (`GAME_TEAM_WIN_COMMENTS`);
- team death / elimination comments (`GAME_TEAM_DEATH_COMMENTS`);
- land/water death comments;
- draw comments.

That made it much easier to understand which internal functions were responsible for which visible game events, and it gave confidence that the reverse-engineered call paths were the right ones.

## Tooling built to support the analysis

To keep the work data-driven, we used and improved `scripts/analyze_result_frames.py`.

That tooling was used to:

- inspect captured `captures/*.jsonl` endgame windows;
- compare multiple games with known winners;
- inventory recurring packet families near game end;
- parse `.WAgame` replay task/message streams;
- line up replay evidence with live-capture evidence.

One useful improvement was teaching the script to locate the replay task/message stream using the replay chunk layout directly instead of depending only on older marker-based guesses.

## How the live detector changed

The old detector in `src/wormnetbot/game_host.py` depended on ad-hoc raw hex prefixes. It worked sometimes, but it was too noisy and too easy to break when the endgame packet mix changed.

The new detector is based on normalized packet families.

### Core additions

- `_packet_family(body: bytes) -> str`
  Normalizes a raw channel-2 packet body into a stable family identifier.

- `_slot_from_endgame_family(family: str) -> int | None`
  Extracts an explicit winning/elimination slot from slot-coded endgame families when present.

- `ENDGAME_SLOT_BODY_MARKERS`
  Exact packet bodies that are strong slot-specific winner signals.

- `ENDGAME_SLOT_FAMILY_MARKERS`
  Family-level slot markers used for weighted scoring near the end of the game.

### New inference model

For 1v1 games:

- inspect a recent window of incoming endgame frames;
- convert each packet to a normalized family;
- score slot 1 and slot 2 using exact-body hits plus family hits;
- weight newer packets more heavily than older ones;
- only declare a winner if the top score clears a minimum threshold and beats the other slot decisively.

For multi-team games:

- build the same recent family window;
- extract slot numbers from slot-coded families such as `401e0302`, `401f0502`, `4021051e`, etc.;
- accumulate weighted scores per real team slot;
- declare the winner only when one slot is clearly ahead.

The capture log now also records the family window and score reasons, which makes future debugging much easier.

## results

The detector was repeatedly validated against labeled captures.

Important milestones:

- an early pass reached `covered=15/18 correct=14/18`;
- marker refinement fixed the misses by narrowing over-broad families and adding missing slot-2 patterns;
- the 1v1 corpus then reached `covered=18/18 correct=18/18`;
- live testing later confirmed correct winner inference in a 1v1 game where slot 2 won;
- after adding the multi-team fallback, live testing also succeeded in 4-team and 6-team style validation runs, including a successful 6-team winner inference.

## assumptions

- WA decides winners from local team/ally survival state, not from a single obvious remote "winner packet".
- The network still exposes enough structure near game end to infer the winner reliably.
- The best practical approach for `Rbot` is to score endgame packet families, not to depend on one raw packet signature.
- Multi-team games need explicit slot-aware handling; a 1v1-only detector is not enough for broader validation.




- improved live winner inference in `src/wormnetbot/game_host.py`;
- better replay-analysis support in `scripts/analyze_result_frames.py`;
- updated project documentation in `README.md` and this file.

The local reverse-engineering inputs are intentionally not included:

- the special WA build with symbols;
- local text dumps and one-off artifacts that were only used during investigation.

## Remaining work

## 2026-05-27: Ghidra WA.exe cross-reference (Windows binary)

This section documents the **official WA.exe** analysis done via Ghidra on VM 101
(`192.168.1.59:8080`), cross-checked against synced 2-client captures and the
new decoder in `src/wormnetbot/wa_task_stream.py`.

### Ghidra access notes

- **API:** `http://192.168.1.59:8080/decompile_function?address=<VA>`
- **Symbol names:** listed in repo `WA.txt`; Ghidra currently exposes **`FUN_*`**
  names unless a PDB is applied. Use **addresses from `WA.txt`**, not name search.
- **`searchFunctions?query=...`** returns empty in this project — address-based
  decompile is the reliable path.

### TaskMessageType encoding

From `TaskMessage::msg_expand` @ **`0x00564EA0`** and `msg_compress` @
**`0x005648B0`**:

| Decimal type | Wire tag | Ghidra case | Body layout (expand) |
|---|---|---|---|
| **1020** | **`0x14`** | *(not in msg_compress switch — returns 0)* | Announced in `401e` as **`0c 14 <idx>`** |
| **1043** | **`0x2B`** | `msg_expand` + `msg_compress` case **`0x2b`** | **2 bytes:** `[0x2B][team_index]` → body dword = 2nd byte |
| 1019 | `0x13` | case **`0x13`** | **3 bytes:** `[0x13][b0][b1]` — *not* surrender; do not treat `0c13` in bulk `401e` as team index |
| — | `0x0C` | case **`0x0c`** | **6 bytes** — explains why `0c 13 …` inside `401e` containers is often a **6-byte record**, not `0c` + type `0x13` |

Rule: **`TaskMessageType = wire_tag + 1000`**.

### Key WA.exe functions (addresses from `WA.txt`, bodies from Ghidra)

| Symbol | VA | Role |
|---|---|---|
| `TaskMessageFifo::put_message` | **`0x00541130`** | Alloc + enqueue `(type, body)` |
| `Task_Worm::fire_surrender` | **`0x0051E5C0`** | User surrender → virtual **`deliver`** |
| `Task::deliver` | **`0x00562EF0`** | Resolves active task, calls vtable **`+0x08`** |
| `Task_TurnGame::surrender_team` | **`0x0055BB50`** | Ally/survival elimination → deliver **1043** |
| `Task_TurnGame::process_surrender` | **`0x005611E0`** | Rank/multi-team flush → **`put_message(0x2B, team_index)`** per team |
| `Task_TurnGame::flush_surrendered_teams` | **`0x00561040`** | Public elimination comments (local UI) |
| `Task_TurnGame::issue_next_win_message` | **`0x0055D270`** | Win fanfare / commentary steps |
| `Task_TurnGame::game_is_over` | **`0x0055CC40`** | Terminal state when one side remains |
| `Task_TurnGame::message` | **`0x0055DC00`** | Dispatches incoming task messages to handlers + relay |
| `TaskMessage::msg_compress` | **`0x005648B0`** | Stream → wire bytes |
| `TaskMessage::msg_expand` | **`0x00564EA0`** | Wire bytes → `(type, body)` |
| `GameTask::comment_public` | **`0x005480F0`** | On-screen winner/elimination text (local) |

Linux symbolized build (`game/WA/WA`) has the **same logic** at different VAs; use
**WA.exe** for Windows wire captures and **WA** for headless/script RE.

### Surrender path (type **1043** / wire **`0x2B`**)

**`surrender_team` @ `0x0055BB50`:**

```c
local_408[0] = param_2;  // team index (0-based in practice)
(**(code **)(*param_1 + 8))(param_1, 0x2B, 0x408, local_408);  // Task::deliver
```

**`process_surrender` @ `0x005611E0`:** loops teams, calls
`put_message(0x2B, &team_index)` (`FUN_00541130`).

**`Task_TurnGame::message` case `0x2B` @ `0x0055DC00`:**

- Reads surrendered team from **`*param_5`**
- Calls **`FUN_00553bd0`** (network relay helper) to forward to peers
- Updates local team state / fanfare hooks

**On the wire (when present):** scan C2 bodies for **`0c 2b <team_index>`** inside
`401e`/`msg_save` containers, or isolated aligned **`2b <idx>`** records.

### Win path (type **1020** / wire **`0x14`**)

**`issue_next_win_message` @ `0x0055D270`:**

- Walks teams with remaining worms; plays local fanfare via `comment_public` path
- Schedules **`TaskType == 0x15`** entries in the turn-game task list (fanfare steps)
- Does **not** emit a bare 2-byte `0x14` through `msg_compress` (type 1020 is absent
  from the compress switch)

**Explicit win index on the wire** appears in **`401e`** streams as:

```text
0c 14 <team_index>   // team_index is 0-based → lobby slot = index + 1
```

Capture proof: **`20260527T213138Z-rank.jsonl`** — winner **olaaaaa** (slot 2) sends
`401e0202 … 0c 14 01`.

**`Task_TurnGame::message` case `0x7D` subcase:** can call
`Task::deliver(..., 0x14, 0x7E, 0x408, local_818)` with `{current_team, 1, step}` —
another win-commentary deliver, not the same bytes as the `0c14` capture marker.

### Rank fast-surrender (no `0c14` win packet)

When the loser surrenders before the winner runs the full `401e` win burst:

| Capture | Surrenderer | Winner | Signal |
|---|---|---|---|
| `212224Z-rank` | **s** (slot 1) | **ss** (slot 2) | **s** alone sends **`400204`** ladder (6×); no `401e`, no `0c14` |
| `Intermediate` | **ss** (slot 2) | **s** (slot 1) | **ss** alone sends `401e`/`400204` endgame (3× ladder); no `0c14` |

Fallback (implemented): if no `0c14`/`0c2b` hit and exactly one human team has
**`400204` ladder frames** while the other has zero → ladder sender is the **loser**.

### Rbot implementation

| File | Purpose |
|---|---|
| `src/wormnetbot/wa_task_stream.py` | `parse_win_announcements`, `parse_surrender_announcements`, `announced_result_from_bodies`, `count_400204_ladder_frames` |
| `src/wormnetbot/game_host.py` | `_parse_announced_winner` — replaces 4020/4021 family scoring |
| `scripts/validate_winner_announce.py` | Offline regression vs `captures/result_labels.json` |
| `captures/result_labels.json` | Ground truth for the three surrender tests above |

**Validation (2026-05-27):** strict decode `1/5`; ladder heuristic `5/5` (see research run below).

Production inference reasons: `task-1020`, `task-1043` only; `task-1020-ladder` is log-only hint.

### Endgame desync (213138)

**s** (loser) sent **`400600`** early while **olaaaaa** (winner) was still in win
fanfare (`401e` burst). Fix: `_maybe_synthesize_missing_endgame_sentinels` now targets
players with **`401e` fanfare** who have **not** yet sent `400600` after the peer
has — not “whoever sent the burst first”.

### What *not* to use

- **4020/4021** slot-family scoring as primary winner detection (removed).
- **`0c13`** bytes inside bulk `401e` as surrender — that is **`msg_expand` case
  `0x13` (type 1019)** or **`0x0C` 6-byte record** framing, not type 1043.
- Isolated **`2b`** bytes in encrypted bulk frames — require mappable team index
  (`<= 8` and in lobby slots).

### Remaining RE (optional)

- Trace **`FUN_00553bd0`** → exact copy into channel-2 `401e`/`400204` wrappers.
- **`DD_Game::msg_save` @ `0x0056FAF0`** — container layout for ladder templates.
- Draw / simultaneous-death paths through `game_is_over` + `process_surrender`.
- Apply PDB in Ghidra so `searchFunctions` matches `WA.txt` names.

---

## 2026-05-27: Endgame research run (Ghidra + corpus + labeled captures)

### Method

1. **Ghidra WA.exe** — decompiled `put_message`, `surrender_team`, `process_surrender`,
   `issue_next_win_message`, `Task_TurnGame::message` (case `0x2B`), `msg_expand`.
2. **Linux symbolized WA** — `wa_net_research.py` / `nm` anchors match same symbol names.
3. **Corpus scan** — all `captures/*.jsonl` for framed **`0c 14 <idx>`** and **`0c 2b <idx>`**
   (requires idx ≤ 8; filters encrypted false positives).
4. **Labeled regression** — `scripts/research_endgame_matrix.py` vs `result_labels.json`.

No Worms2D-specific docs were found under `docs/` (only `NETWORK_HANDSHAKE.md` for channel-2
sync/relay). `third_party/wkJellyWorm` is unrelated mod code.

### Ghidra-confirmed semantics

| Task type | Wire tag | Emit path | On-wire when present |
|---|---|---|---|
| **1043** surrender | **`0x2B`** | `surrender_team` → `Task::deliver(..., 0x2B, &team)`; `process_surrender` → `put_message(0x2B, team)` | Framed **`0c 2b <idx>`** in `401e`, or aligned **`2b <idx>`** (2-byte msg_expand record) |
| **1020** win commentary | **`0x14`** | `issue_next_win_message` drives **local** fanfare; explicit team index appears in **`401e`** as **`0c 14 <idx>`** (idx 0-based → slot = idx+1) | **Not** in `msg_compress` switch — no bare `0x14` compress record |

**`Task_TurnGame::message` case `0x2B`:** if surrendered team matches active team, calls
**`FUN_00553BD0`** (network relay) before local state update.

### Corpus hits (all captures)

| Signal | Count | Notes |
|---|---|---|
| Framed **`0c14`** (task-1020) | **3** | 2× Elite League (`spadge`), 1× rank test (`olaaaaa` @ 213138) |
| Framed **`0c2b`** (task-1043) | **1** | Elite League only (`pepoc` @ 082026) |
| Isolated **`2b xx`** (idx≤7) | 38 | Mostly Elite League bulk `401e`; need slot context to trust |

### Labeled May-27 games — finish-path matrix

| Capture | Outcome | Decodable on wire? | What actually happened |
|---|---|---|---|
| **213138** | olaaaaa wins, **s** surrenders | **Yes** — `0c14 01` from olaaaaa (slot 2) | Winner ran full `401e` win burst |
| **212224** | ss wins, **s** fast-surrenders | **No** | **s** alone sent `400204` ladder (6×); no `401e`, no `0c14`, no valid `0c2b` |
| **202045** | s wins, **ss** surrenders | **No** | **ss** alone sent endgame ladder (3×); no announcements |
| **215936** | s wins, ola quit early | **No** | **s** sent ladder (7×); ola sent `400600` first |
| **220301** | s wins, both sent ladder | **No** | Both had `400204` frames; no `0c14` |

**Strict decode (task-1020/1043 only): 1/5** match labels.  
**Ladder heuristic: 5/5** — empirical, **not** Ghidra-backed announcements.

### Product decision (2026-05-28)

- **Rbot declares winner only on strict decode** (`task-1020` / `task-1043` from wire).
- **No heuristics** — no ladder counts, no first-`400600`, no fanfare silence/min, no slot-family scoring.
- Rank fast-surrender often has **no decodable `0c14`/`0c2b` on C2**; until `put_message`→GameNet framing is traced, Rbot correctly stays silent.

### Scripts

| Script | Purpose |
|---|---|
| `scripts/research_endgame_matrix.py` | Full corpus + labeled matrix report |
| `scripts/validate_winner_announce.py --strict` | Regression without ladder fallback |
| `scripts/c2_endgame_type_byte_survey.py` | Raw type-byte survey (noisy; use with care) |

### Next RE (to raise strict decode rate)

1. **Frida** — `scripts/frida_wa_endgame_trace.js` hooks `put_message` (RVA `0x141130`) and `WorldRootEntity__SurrenderTeam` (`0x15BB50`) on Windows; log to `endgame_trace.jsonl` during surrender. Config: `scripts/wa_frida_config.example.json`.
2. Trace **`GameMessageRouter` / `GameNet::send_block`** — when does `deliver(0x2B)` actually become channel-2 bytes? **Rank fast-surrender captures have zero `0c2b`/`0c14` in C2** (probe: `scripts/gamenet_re_probe.py` on `20260528T151255Z-rank.jsonl`).
3. **`5c1f0202` container** — uint16 LE chunks after magic; rank surrender burst is chunk `40001d0c1e8a80f23321` (no `0c2b`). Decoder: `wa_gamenet_containers.py`.
4. **Elite League** — framed `0c2b` appears inside `44020001…` bodies (`20260422T082026Z-EliteLeague.jsonl`); strict parse works there.
5. **GameNet LZ77** — `GameNet__update_incoming_1` seeds bitreader from first byte @ `+0x25b`; our `lz77_decompress_maybe` does not yet match `4070…` blocks in rank captures (still open).
6. Apply **PDB in Ghidra** so HTTP API names match `WA.txt` (searchFunctions currently empty).

---

## 2026-05-28: OpenWA catalog integration

Vendored [OpenWA](https://github.com/paavohuhtala/OpenWA) `re/` under
`third_party/OpenWA-re/` (408 TOML files, validated). See `docs/OPENWA.md`.

### EntityMessage (replaces ad-hoc TaskMessageType notes)

| OpenWA / wire | Decimal +1000 | Role |
|---|---|---|
| `Surrender` **0x2B** | 1043 | `SurrenderMessage { team_index }` — menu / elimination |
| `TeamVictory` **0x14** | 1020 | Win commentary; on C2 often `0c 14 <idx>` in `401e` |
| `MachineQuit` **0x0D** | 1013 | **`BeginNetworkGameEnd`** 12-byte net handshake (NOT surrender) |
| `TurnEndMaybe` **0x75** | 1117 | Broadcast when entering `ROUND_ENDING` |

`msg_expand` / `msg_compress` @ **0x564EA0** / **0x5648B0** — same VAs as our Ghidra pass.

### Network end handshake (wormstv "PLEASE WAIT")

OpenWA Rust port (`GameRuntime__BeginNetworkGameEnd` @ **0x536270**):

1. Sets `game_state = NETWORK_END_STARTED` (3)
2. Builds 12-byte buffer: `[0x0D, starting_team_index, 1]` (`MachineQuit`)
3. `NetSession.submit_message_buffer` + `GameNet.send_block`
4. `OnNetworkEndAwaitPeers` waits on `net_end_countdown` (500 frames) + peer scores
5. UI: `RenderNetworkEndWaitTextbox` @ **0x534E00** — token 0x6D0 "PLEASE WAIT %d SEC"

This is **above** channel-2 TCP relay (`400600` / `c00d0100`). Rbot must satisfy both layers.

### Ghidra VM 101

Import manifest: `third_party/OpenWA-re/wa_import.json` via `OpenWAImport.java`.
Cross-check: `python3 scripts/openwa_re_crosscheck.py`.

### Symbol renames (OpenWA vs WA.txt)

| WA.txt (legacy) | OpenWA name | VA |
|---|---|---|
| `Task_TurnGame::surrender_team` | `WorldRootEntity__SurrenderTeam` | 0x55BB50 |
| `Task_TurnGame::flush_surrendered_teams` | `WorldRootEntity__flush_surrendered_teams` | 0x561040 |
| `Game::setup_netquit` | `GameRuntime__BeginNetworkGameEnd` | 0x536270 |
| `Game::update_netclose` | `GameRuntime__OnNetworkEndAwaitPeers` | 0x536470 |

## Rank wire RE (2026-05-28)

Corpus: **93** `*rank*.jsonl` captures under `captures/` (probe: `scripts/probe_rank_wire_corpus.py`).

| Metric | Value |
|---|---|
| Framed **`0c14`** (task-1020) in any C2 body | **4 / 93** |
| Rank fast-surrender (`20260528T151255Z-rank.jsonl`) | **no** `0c14`, **no** `0c2b`; `5c1f` + `4070` markers present |
| **`4070`… LZ77** vs task stream | **Not** decodable with `lz77_decompress_maybe` → task tags (open) |
| Ground truth for arena tests | **OpenWA sidecar** (`winner_inferred` reason `openwa-arena`) |

**Product:** Rbot still declares winner only on **strict** task-1020/1043 decode; `wire_re_gap` capture events record corpus flags on decode miss (no ladder/heuristic inference).


## Rank 401e win framing (2026-06-01)

Wire task-1020 in `401e` bodies often uses `0c <marker> <team> 0c 14 <junk>` (markers
`0xc0`, `0xcc`, not only elite `0xb4`). Team index is the byte **before** `0c 14`.
Labeled capture: `20260601T073140Z-rank.jsonl` (OpenWA slot 2). Strict decode: `task-1020`.

Vanilla test: expect log `WA winner inferred from task stream` (not `openwa-arena`).
Offline check: `./scripts/replay_wire_winner.py captures/<file>.jsonl`

## Ghidra endgame chain (2026-06-01, wormstv WA.exe)

Connected: `http://192.168.1.59:8080/decompile_function?address=0x...`

### Surrender (task 1043 / wire 0x2B)
- `WorldRootEntity__SurrenderTeam` @ `0x0055BB50` → `HandleMessage(0x2B, …)` with **team index in payload** (0-based team id in local buffer).
- `EntityMessage__msg_expand` case `0x2B`: 2-byte record `[2B][team]` → 4-byte body dword = team byte.
- Routed on wire via `GameNet::send_block` → LZ77 → WormNET ch2 (often inside `401e*` / `5c1f*` containers).

### Win commentary (task 1020 / wire 0x14)
- `BaseEntity__deliver(..., 0x14, …)` from turn-event / victory paths (`WorldRootEntity__process_turn_event` case 8, etc.).
- On captures, reliable marker: **`401e0202` container** with inner **`0c 14 <team_byte>`** (team byte is **human 0-based**: `01` → lobby slot 2 in 2p tests).
- `WorldRootEntity__issue_next_win_message` @ `0x0055D270` walks an internal **0x15 (GameOver) task queue** — it is **not** the function that writes `0c14` to the network blob.

### `401e0102` vs `401e0202` (rank captures)
| Magic | Seen from | `0c14` win tag |
|-------|-----------|----------------|
| `401e0202` | Winner side (e.g. blue2 after red surrenders) | Often present |
| `401e0102` | Endgame from other peer (e.g. red after red **won**) | **No** — inner `0c62…` only |

`401e0102` was missing from RBot `MSG_SAVE_MAGICS` (only `401e0202` scanned). Added `401e0102` so we at least parse the inner stream; **still no substitute for missing `0c14`** when WA does not emit it.

### Why “all the time” fails on strict wire
RBot can only relay/decode what the **winning client** puts through GameNet. If that process only sends `401e0102` / `0c62` fanfare without `0c14`, there is **no task-1020 on the wire** — not a lobby/slot bug.

Next RE target: what triggers `401e0202`+`0c14` vs bare `401e0102` on the **winning** machine (same build, same surrender — compare `080246Z` vs `080819Z` in-process, not more roster work).


### RE: HandleMessage / SendGameState branch (2026-06-01)

**Call graph (Ghidra HTTP + metrics):**
- `TurnManager__ProcessFrame` → `issue_next_win_message` (internal 0x15 queue + `GameTask__comment_public` only).
- `TurnManager__ProcessFrame` → `process_turn_events` → `process_turn_event` → `deliver(0x14, 0x59/0x5a/0x5b/…)` for win fanfare steps.
- `HandleMessage` case `0x2B`: surrender UI/router (not the same as wire `0c2b` record).
- `HandleMessage` case `0x7d`, sub-op `0x45`: `deliver(0x14, 0x7e, …)` with team `param_1[0x4b]` when build `>= 0x1e4`.
- `check_for_vital_deaths` / `check_for_survival_deaths` → `SurrenderTeam` → `HandleMessage(0x2B)`.
- `GameNet__update_application` → `msg_expand` (inbound decode); `DDNetGameWrapper__SendGameState` → `msg_expand` + `PushMessage` (outbound serialize from replay/state buffer).
- `BeginNetworkGameEnd` / `update_network_game` → `GameNet__send_block`.

**Capture correlation (who sends what):**
| Game | Winner | Sender | Magic | `0c14` |
|------|--------|--------|-------|--------|
| 080246Z | slot 2 blue2 | blue2 | `401e0202` | yes |
| 080246Z | — | red (loser) | `401e0102` | no |
| 080819Z | slot 1 red | red (winner) | `401e0102` | no (`0c62` only) |

**Conclusion:** `401e` byte 3 (`01` vs `02`) marks **container subtype on the flushing client**, not lobby slot. Slot-2-wins does not always produce `401e0202`+`0c14` (080819Z counterexample for slot 1). `msg_expand` case `0x62` (version > `0x1c`) has **no team byte** — cannot replace task-1020 decode.

**RBot implication:** keep task-1043 surrender inference; add optional winner hints from `401e0202`+`0c14` when present; do not treat `401e0102`-only from winner as task-1020.
