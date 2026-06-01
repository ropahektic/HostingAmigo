"""Read OpenWA team_arena winner export (non-heuristic engine truth).

OpenWA writes JSON when ``hud_status_code`` enters game-over (6 or 8) or on
ENTITY Surrender (may still report hud 0 before HUD catches up).
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from pathlib import Path


LOGGER = logging.getLogger(__name__)

_VALID_HUD = frozenset({0, 6, 8})


@dataclass(frozen=True, slots=True)
class OpenwaWinnerSidecar:
    hud_status_code: int
    written_unix_ms: int
    survivor_team_idx_1based: tuple[int, ...]
    winner_team_idx_1based: int | None
    loser_team_idx_1based: int | None
    raw: dict[str, object]

    def resolve_lobby_slots(self, valid_slots: set[int]) -> tuple[int, int | None] | None:
        """Map sidecar 1-based team indices to lobby slots in ``valid_slots``."""
        if self.winner_team_idx_1based is not None:
            w = self.winner_team_idx_1based
            if w in valid_slots:
                loser = self.loser_team_idx_1based
                if loser is not None and loser not in valid_slots:
                    loser = None
                if loser is None and len(valid_slots) >= 2:
                    loser = next((s for s in valid_slots if s != w), None)
                return w, loser

        human_survivors = [s for s in self.survivor_team_idx_1based if s in valid_slots]
        if len(human_survivors) == 1:
            winner_slot = human_survivors[0]
            loser_slot = next((s for s in valid_slots if s != winner_slot), None)
            return winner_slot, loser_slot
        return None


def clear_openwa_winner_sidecar(path: Path) -> None:
    try:
        path.unlink(missing_ok=True)
    except OSError as exc:
        LOGGER.debug("Could not clear OpenWA winner sidecar %s: %s", path, exc)


def read_openwa_winner_sidecar(
    path: Path,
    *,
    not_before_unix: float | None = None,
    log_missing: bool = False,
) -> OpenwaWinnerSidecar | None:
    """Load and validate sidecar JSON. Returns None if missing, stale, or invalid."""
    if not path.is_file():
        if log_missing:
            LOGGER.info("OpenWA winner sidecar configured but missing: %s", path)
        return None
    try:
        raw_text = path.read_text(encoding="utf-8")
        payload = json.loads(raw_text)
    except (OSError, json.JSONDecodeError) as exc:
        LOGGER.debug("OpenWA winner sidecar unreadable %s: %s", path, exc)
        return None
    if not isinstance(payload, dict):
        return None

    try:
        hud = int(payload.get("hud_status_code", 0))
        written_ms = int(payload.get("written_unix_ms", 0))
    except (TypeError, ValueError):
        return None

    survivors_raw = payload.get("survivor_team_idx_1based")
    survivors: list[int] = []
    if isinstance(survivors_raw, list):
        for item in survivors_raw:
            try:
                survivors.append(int(item))
            except (TypeError, ValueError):
                continue

    winner: int | None = None
    loser: int | None = None
    if payload.get("winner_team_idx_1based") is not None:
        try:
            winner = int(payload["winner_team_idx_1based"])
        except (TypeError, ValueError):
            winner = None
    if payload.get("loser_team_idx_1based") is not None:
        try:
            loser = int(payload["loser_team_idx_1based"])
        except (TypeError, ValueError):
            loser = None

    if winner is None and len(survivors) == 1:
        winner = survivors[0]

    # hud 0 is valid when arena export has winner/survivor data (Surrender entity path).
    if hud not in _VALID_HUD:
        return None
    if hud == 0 and winner is None and not survivors:
        return None

    if not_before_unix is not None:
        file_age = path.stat().st_mtime
        if file_age + 0.05 < not_before_unix:
            return None
        if written_ms and written_ms < int(not_before_unix * 1000) - 500:
            return None

    return OpenwaWinnerSidecar(
        hud_status_code=hud,
        written_unix_ms=written_ms,
        survivor_team_idx_1based=tuple(survivors),
        winner_team_idx_1based=winner,
        loser_team_idx_1based=loser,
        raw=payload,
    )


def sidecar_path_from_config(path_str: str) -> Path | None:
    stripped = path_str.strip()
    if not stripped:
        return None
    return Path(stripped).expanduser()
