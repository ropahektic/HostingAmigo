# WormNETBot

Standalone WormNET bot for hosting Worms Armageddon games on WormNET.

**Reliable for playing a full rank match with two independent human clients.** The bot is a headless host that relays WA lobby and channel-2 traffic so peers can load, play turns, and reach the result screen without a real WA host process.

The idea of this project is to make competitive worms self contained inside the Bot to minimize user workload when playing and reporting competitive games. The bot will contain the whole environment: ranking, player stats, matchmaking.

## Current status

The bot can host Worms Armageddon sessions over WormNET with IRC advertising, a WA-compatible TCP listener, lobby/game relay logic, and captures.

What works well:

- IRC/WormNET connectivity with reconnect loop
- game advertisement create/close via `wormageddonweb/Game.asp`
- WA host listener on the advertised game port
- join handshake, **team add / colour / worm-count sync** for multiple clients
- **two-client load handshake and in-game channel-2 relay** (the main breakthrough — peers sync and play a full match)
- scheme configuration and manual game start from IRC
- channel-2 relay modes for loading and gameplay traffic
- per-session capture logging to `captures/*.jsonl`
- replay/capture analysis tooling in `scripts/analyze_result_frames.py`
- GameNet wire decode helpers (`wa_lz77.py`, `wa_gamenet_wire.py`, `wa_task_stream.py`)

**Still imperfect:**

- **Endgame network handshake** is relay-only today. Matches finish and both clients reach the result screen, but often after a ~10s **"Waiting for players"** PLEASE WAIT fallback instead of the instant transition vanilla WA shows after fanfare.
- **Winner / match outcome** from wire traffic is still unresolved — see [Winner detection (status)](#winner-detection-status).
- Lobby **ready / light bulb** quirks can still appear with multiple humans.

Notes on reverse-engineering (protocol, endgame-shaped packets, tooling) are in `Findings.md`.

## Quick start

1. Create and edit a local env file from `.env.example`.
2. Run:

```bash
python3 run_bot.py
```

Or install editable and use the script entrypoint:

```bash
python3 -m pip install -e .
wormnetbot
```

On Linux, keep `WORMNET_GAME_BIND_HOST=0.0.0.0` so the bot can own `17011` for remote WA clients.

## Winner detection (status)

Efforts were made to infer the winner from live hosted traffic, but **no dependable method exists yet** beyond weak heuristics. The closest usable hint is **who had the last turn before the session stops** (player/team), which still must not be treated as authoritative match results.

Supporting tooling (captures, offline analysis):

- `captures/*.jsonl` — raw packets from hosted sessions
- `scripts/analyze_result_frames.py` — replay/capture analysis helpers
- `src/wormnetbot/game_host.py` — strict task-1020/1043 decode path (often misses on rank surrender)

Background draws on an unstripped WA build and `text strings` material kept out of this repo; narrative and experiments live in `Findings.md`.

## Environment variables

- `WORMNET_HOST` IRC host
- `WORMNET_PORT` IRC port
- `WORMNET_PASSWORD` shared IRC PASS
- `WORMNET_NICK` bot nickname
- `WORMNET_USERNAME` USER field
- `WORMNET_REALNAME` realname/gecos field
- `WORMNET_CHANNELS` comma-separated channels to join
- `WORMNET_COMMAND_PREFIX` command prefix, default `!`
- `WORMNET_REPLY_TARGET` `channel` or `private`
- `WORMNET_RECONNECT_SECONDS` reconnect delay
- `WORMNET_LOG_LEVEL` logging level
- `WORMNET_WEB_BASE_URL` base URL for `wormageddonweb` HTTP endpoints
- `WORMNET_GAME_CHANNEL` channel name used in `Game.asp`
- `WORMNET_GAME_HOST_IP` IP advertised to clients as game host
- `WORMNET_GAME_LOCATION` location code sent to `Game.asp`
- `WORMNET_GAME_TYPE` game type sent to `Game.asp`
- `WORMNET_GAME_BIND_HOST` local interface used for the WA host listener
- `WORMNET_GAME_PORT` local WA host port, default `17011`
- `WORMNET_GAME_C2_RELAY` relay mode: `gameplay` (default, relays channel-2 during loading/gameplay) or `minimal` (narrow tests only)
- `WORMNET_WA_START_GAME_VERSION` decimal or `0x…` dword in `0x1C` (default `500` / `0x1F4` for WA 3.8.x)
- `WORMNET_ENV_FILE` optional override path for the env file

## Supported commands

- `!help`
- `!ping`
- `!echo <text>`
- `!jost <scheme> [game name]`
- `!color <team> <color 1-6>`
- `!ready`
- `!start`
- `!close`
- `!status`

## Notes

- Only one hosted game is managed at a time. It's easily expandable to many simultaneously in a future patch.
- Captures are written automatically to `captures/` for debugging and protocol analysis.
- Replay-assisted reverse-engineering tooling lives in `scripts/analyze_result_frames.py`.
- Some lobby snapshots currently include a synthetic host placeholder team in slot `0`; this is an artifact of the current emulation and should not be treated as a real playable team.
- Local reverse-engineering inputs such as the symbolized WA binary are kept out of git; the repo only contains the reusable tooling and conclusions.

## Remaining gaps

- **Winner inference:** need a validated on-wire signal (today: last-turn hint only).
- **Endgame GameNet assist:** emulate `BeginNetworkGameEnd` / `MachineQuit` so clients skip the PLEASE WAIT countdown.
- Keep widening validation coverage across more game formats, schemes, and edge-case finishes.
- Improve map/scheme coverage and polish lobby emulation.
- Add channel/user access control and other operational safeguards.

## License

[0BSD](https://opensource.org/licenses/0BSD) (zero-clause BSD). Use, modify, and distribute with no conditions beyond the disclaimer in `LICENSE`.
