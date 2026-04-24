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

## Validation results

The detector was repeatedly validated against labeled captures.

Important milestones:

- an early pass reached `covered=15/18 correct=14/18`;
- marker refinement fixed the misses by narrowing over-broad families and adding missing slot-2 patterns;
- the 1v1 corpus then reached `covered=18/18 correct=18/18`;
- live testing later confirmed correct winner inference in a 1v1 game where slot 2 won;
- after adding the multi-team fallback, live testing also succeeded in 4-team and 6-team style validation runs, including a successful 6-team winner inference.

## What we now believe with confidence

- WA decides winners from local team/ally survival state, not from a single obvious remote "winner packet".
- The network still exposes enough structure near game end to infer the winner reliably.
- The best practical approach for `Rbot` is to score endgame packet families, not to depend on one raw packet signature.
- Multi-team games need explicit slot-aware handling; a 1v1-only detector is not enough for broader validation.

## Repository impact

The reusable results of this work are kept in the repository:

- improved live winner inference in `src/wormnetbot/game_host.py`;
- better replay-analysis support in `scripts/analyze_result_frames.py`;
- updated project documentation in `README.md` and this file.

The local reverse-engineering inputs are intentionally not included:

- the special WA build with symbols;
- local text dumps and one-off artifacts that were only used during investigation.

## Remaining work

This is a strong step forward, but not the end of validation.

The main remaining work is to keep testing:

- more schemes and map situations;
- unusual finishes such as draws or simultaneous deaths;
- more multi-team outcomes with different slot layouts;
- any cases where host/client ordering or relay timing changes the endgame window.

At this point, though, `Rbot` is no longer guessing blindly. It has a winner detector built from observed live traffic, replay correlation, and WA's own internal game logic.
