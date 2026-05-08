# WormNETBot

Standalone WormNET bot for hosting Worms Armageddon games on WormNET.

**Reliable today with one human in the bot’s game.** Multiple real clients in the same session still hit lobby/ready desync; see [Current status](#current-status).

The idea of this project is to make competitive worms self contained inside the Bot to minimize user workload when playing and reporting competitive games. The bot will contain the whole environment: ranking, player stats, matchmaking.

## Current status

The bot can host Worms Armageddon sessions over WormNET with IRC advertising, a WA-compatible TCP listener, lobby/game relay logic, captures, and winner inference — **but multi-human sessions are not reliable today** (see below).

What works well:

- IRC/WormNET connectivity with reconnect loop
- game advertisement create/close via `wormageddonweb/Game.asp`
- WA host listener on the advertised game port
- join handshake, **team add / colour / worm-count sync** (multiple clients can pick teams without drifting colours/slots in typical tests)
- scheme configuration and manual game start from IRC
- channel-2 relay modes for loading and gameplay traffic
- per-session capture logging to `captures/*.jsonl`
- replay/capture analysis tooling in `scripts/analyze_result_frames.py`
- live winner inference from endgame packet families where the game reaches a normal finish (validation has focused on **one human** joining the bot-hosted game)

### Important: only one joining client is supported for a full, stable roundtrip

After extensive testing with **more than one real WA client** in the same bot-hosted game, the **pre-game lobby** (ready **light bulb**, “waiting for players”, etc.) **desynchronizes**. Symptoms include inconsistent ready indicators: acting on one client (e.g. toggling the bulb) can affect **other** clients’ ready state or bulb UI in ways that do not match a normal WA host. **Team selection tends to stay in sync**; the breakage is mainly **pre-start lobby / ready orchestration**. Edge cases worsen if someone **joins, selects a team, then leaves**, or similar churn.

**As of now, assume the bot only completes a whole game reliably when exactly one human joins the advertised session.** Using multiple humans is experimental and likely to stall or confuse the lobby — not a supported configuration.

The recent work on this project focused on mirroring WA's own local endgame logic closely enough to infer the winner from live channel-2 traffic instead of relying on manual reporting. The reverse-engineering notes and the path from the symbolized WA build to the current detector are documented in `Findings.md`.

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

## Winner detection approach

Winner inference is based on the end of the live game packet stream, not on lobby metadata.

- `captures/*.jsonl` stores raw packet captures from live hosted games.
- `scripts/analyze_result_frames.py` parses captures and replay task/message streams to compare endgame traffic against known outcomes.
- `src/wormnetbot/game_host.py` normalizes channel-2 packets into stable packet families and scores recent endgame families to infer the winning slot.
- For multi-team games, the detector falls back to slot-coded endgame families so that a winning slot can still be attributed when more than two non-host teams played — **when the match actually reaches endgame traffic**. That presumes a session that got past lobby/start; use **one joining client** if you need that outcome to be reachable via this bot host today.

This work was guided by an unstripped WA build with symbols plus the in-game `text strings` dump, but those local reverse-engineering artifacts are intentionally not part of the repository.

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
- `WORMNET_GAME_C2_RELAY` relay mode: `gameplay` (default, relays channel-2 during loading/gameplay) or `minimal` (narrow tests only). This does **not** fix multi-client lobby desync; use one human client for stable play.
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

- **Multi-human lobby:** reproduce and fix pre-lobby / ready (light bulb) and join–leave edge behaviour so two or more real clients match official WA hosting.
- Keep widening validation coverage across more game formats, schemes, and edge-case finishes.
- Improve map/scheme coverage and polish the lobby emulation for the single-client-supported path.
- Add channel/user access control and other operational safeguards.

## License

This project is released under the MIT License. See `LICENSE`.
