# RBot / OpenWA test protocol (2026-06)

## Do not use first-turn surrender

WA treats **very early surrender** as a **disconnect**, not a normal ranked result.

- Match may not count on WormNET / ladder
- Channel-2 often has **no** task 1020/1043 (our rank corpus is biased this way)
- OpenWA may see Surrender/TeamVictory in memory while GameNet never serializes them

**Minimum:** at least **2 completed turns** (both sides moved), then end the game.

## Scenarios

| ID | Setup | End condition |
|----|--------|----------------|
| **T2-SUR** | RBot + 2 humans | Turn 2+ → ESC → Surrender |
| **T2-ELIM** | Same | Eliminate last worm |
| **ELITE** | Longer match | Natural win / fanfare |
| **VANILLA** | No OpenWA | T2-SUR or T2-ELIM (wire-only production target) |
| **OPENWA-LABEL** | `Start OpenWA for RBot.cmd` | T2-SUR or T2-ELIM + `compare_arena_wire.py` |

## Pre-flight (CT104)

```bash
systemctl is-active wormnetbot
grep OPENWA /opt/WormNETBot/.env
journalctl -fu wormnetbot | grep -E 'Winner inferred|openwa-arena|task stream|wire_re_gap'
```

## Post-game

```bash
cd /opt/WormNETBot && ./scripts/postgame_check.sh
```

Pass: `winner_inferred` with `task-1020` / `task-1043` (vanilla) or `openwa-arena` (label run).  
`WARNING: likely EARLY endgame` → discard capture for RE.
