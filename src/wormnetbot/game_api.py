from __future__ import annotations

from dataclasses import dataclass
import logging
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from .config import BotConfig


LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class HostedGame:
    game_id: int
    name: str
    scheme: str
    owner_nick: str | None


class GameAdvertiser:
    def __init__(self, config: BotConfig) -> None:
        self.config = config

    def create_game(self, owner_nick: str | None, scheme: str, game_name: str | None = None) -> HostedGame:
        self._validate_ready()
        owner = owner_nick or self.config.nickname
        name = (game_name.strip() if game_name else "") or f"{owner}'s game"
        params = {
            "Cmd": "Create",
            "Name": name[:29],
            "Nick": self.config.nickname,
            "HostIP": self.config.game_host_ip,
            "Chan": self.config.game_channel,
            "Loc": self.config.game_location,
            "Type": self.config.game_type,
        }
        url = f"{self.config.web_base_url}/wormageddonweb/Game.asp?{urlencode(params)}"
        request = Request(url, method="GET")
        LOGGER.info("Creating game advertisement via %s", url)
        with urlopen(request, timeout=5) as response:
            header = response.headers.get("SetGameId", "").strip()
            if not header:
                raise RuntimeError("Game creation response missing SetGameId header")
            header = header.lstrip(":").strip()
            try:
                game_id = int(header)
            except ValueError as exc:
                raise RuntimeError(f"Invalid SetGameId header: {header!r}") from exc
            return HostedGame(
                game_id=game_id,
                name=name[:29],
                scheme=scheme,
                owner_nick=owner_nick,
            )

    def close_game(self, game_id: int) -> None:
        self._validate_ready()
        params = {"Cmd": "Close", "GameID": str(game_id)}
        url = f"{self.config.web_base_url}/wormageddonweb/Game.asp?{urlencode(params)}"
        request = Request(url, method="GET")
        LOGGER.info("Closing game advertisement via %s", url)
        with urlopen(request, timeout=5):
            return

    def _validate_ready(self) -> None:
        if not self.config.web_base_url:
            raise RuntimeError("WORMNET_WEB_BASE_URL is not configured")
        if not self.config.game_host_ip:
            raise RuntimeError("WORMNET_GAME_HOST_IP is not configured")
