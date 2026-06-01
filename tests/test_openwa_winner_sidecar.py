from __future__ import annotations

import json
import time
from pathlib import Path

from wormnetbot.openwa_winner_sidecar import (
    clear_openwa_winner_sidecar,
    read_openwa_winner_sidecar,
)


def test_read_sidecar_single_survivor_maps_to_winner(tmp_path: Path) -> None:
    path = tmp_path / "winner.json"
    path.write_text(
        json.dumps(
            {
                "hud_status_code": 6,
                "written_unix_ms": int(time.time() * 1000),
                "survivor_team_idx_1based": [2],
            }
        ),
        encoding="utf-8",
    )
    sidecar = read_openwa_winner_sidecar(path)
    assert sidecar is not None
    resolved = sidecar.resolve_lobby_slots({1, 2})
    assert resolved == (2, 1)


def test_stale_sidecar_rejected_after_game_start(tmp_path: Path) -> None:
    path = tmp_path / "winner.json"
    path.write_text(
        json.dumps(
            {
                "hud_status_code": 8,
                "written_unix_ms": 1,
                "winner_team_idx_1based": 1,
            }
        ),
        encoding="utf-8",
    )
    path.touch()
    old = time.time() - 60
    import os

    os.utime(path, (old, old))
    assert read_openwa_winner_sidecar(path, not_before_unix=time.time() - 5) is None


def test_clear_sidecar(tmp_path: Path) -> None:
    path = tmp_path / "winner.json"
    path.write_text("{}", encoding="utf-8")
    clear_openwa_winner_sidecar(path)
    assert not path.exists()
