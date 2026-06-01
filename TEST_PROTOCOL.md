# Rank winner / wire decode test protocol

Strict production rule: **winner from task-1020 (`0c14`) or task-1043 (`0c2b` surrender) only** — no fanfare silence, arena sidecar, or slot-guessing heuristics.

## Before a live rank test

1. Two **vanilla** clients on **different PCs/networks** when validating wire (same-PC often suppresses `0c14`).
2. Note who won and lobby slots in `captures/result_labels.json` after the game.
3. Confirm bot is running: `systemctl status wormnetbot` on CT104.

## After each rank game

### 1. Offline wire replay (primary)

```bash
cd /opt/WormNETBot
./scripts/replay_wire_winner.sh captures/<TIMESTAMP>-rank.jsonl
```

Corpus + label validation (CI-style):

```bash
./scripts/test_wire_corpus.sh
```

Columns (compact): `capture | decode | winner | wire-flags | vs-label`

| `vs-label` | Meaning |
|------------|---------|
| `OK` | Strict decode slot matches `winner_slot` in labels |
| `OK(miss)` | No wire winner, and label expects `expect_wire: miss` |
| `MISS` | Labeled game but no task-1020/1043 on wire |
| `WRONG` | Decode disagrees with label |
| `-` | No `winner_slot` in labels |

Wire flags (no heuristics, descriptive only):

| Flag | Meaning |
|------|---------|
| `401e02+14` | `401e0202` container with inner `0c14` (strong 1020 path) |
| `401e02` | `401e0202` without `0c14` in same body |
| `401e01` | `401e0102` endgame flush (often no team in `0c62`) |
| `1043?` | Surrender tag / parse hits on wire |
| `5c1f` | Rank chunk container present |

### 2. Live bot log

```bash
journalctl -u wormnetbot -n 40 --no-pager | grep -E 'winner|task-|wire_re_gap|decode miss'
```

Expect on success:

- `WA winner inferred from task stream` with `reason=task-1020` or `task-1043`

On failure:

- `WA winner not announced on wire` and capture row `type=wire_re_gap` in the jsonl

### 3. Label file entry

```json
{
  "capture": "20260601T120000Z-rank.jsonl",
  "winner": "blue2",
  "loser": "red",
  "winner_slot": 2,
  "loser_slot": 1,
  "expect_wire": "1043",
  "note": "T2+ surrender; blue2 won"
}
```

`expect_wire` values:

| Value | Use when |
|-------|----------|
| `1020` | You expect `0c14` / task-1020 on wire |
| `1043` | Surrender endgame; winner = non-surrenderer |
| `miss` | Known good game but WA did not emit strict tags (document why) |
| `any` | Slot must match if decode succeeds |

## Reference captures (June 2026)

| Capture | Winner slot | Strict decode | Wire flags | Notes |
|---------|-------------|---------------|------------|-------|
| `080246Z` | 2 | task-1020 | 401e02+14 | Gold path |
| `083121Z` | 2 | task-1043 | 1043? | Red surrendered |
| `080819Z` | 1 | MISS | 401e01, 0c62 | Winner sent `401e0102` only |
| `075623Z` | 2 | MISS | 401e01?, 5c1f | No `0c14` despite blue win |

## What we do **not** test

- “If slot 2 reports → slot 2 won; else slot 1” — fails `083121Z` and `075623Z`.
- OpenWA `winner.json` sidecar in production (RE labels only).

## RE tools (optional)

```bash
python3 scripts/build_wa_metrics_from_ghidra_http.py http://192.168.1.59:8080 \
  -o scratch/wa_metrics.json --depth 2
python3 scripts/ghidra_metrics_callers.py scratch/wa_metrics.json
```
