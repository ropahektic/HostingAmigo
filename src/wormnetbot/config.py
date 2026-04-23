from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path


def _load_env_file(path: Path) -> None:
    if not path.exists():
        return

    with path.open("r", encoding="utf-8") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip())


def _read_env_file() -> None:
    candidates: list[Path] = []
    override = os.getenv("WORMNET_ENV_FILE", "").strip()
    if override:
        candidates.append(Path(override).expanduser())

    cwd_env = Path.cwd() / ".env"
    package_root_env = Path(__file__).resolve().parents[2] / ".env"
    for candidate in (cwd_env, package_root_env):
        if candidate not in candidates:
            candidates.append(candidate)

    for candidate in candidates:
        _load_env_file(candidate)


@dataclass(slots=True)
class BotConfig:
    host: str
    port: int
    password: str
    nickname: str
    username: str
    realname: str
    channels: list[str]
    command_prefix: str
    reply_target: str
    reconnect_seconds: float
    log_level: str
    web_base_url: str
    game_channel: str
    game_host_ip: str
    game_location: str
    game_type: str
    game_bind_host: str
    game_port: int
    game_c2_relay: str  # "minimal" | "gameplay" (see WORMNET_GAME_C2_RELAY)

    @classmethod
    def from_env(cls) -> "BotConfig":
        _read_env_file()
        c2 = os.getenv("WORMNET_GAME_C2_RELAY", "minimal").lower().strip()
        if c2 not in ("minimal", "gameplay"):
            c2 = "minimal"
        channels = [
            channel.strip()
            for channel in os.getenv("WORMNET_CHANNELS", "#AnythingGoes").split(",")
            if channel.strip()
        ]
        return cls(
            host=os.getenv("WORMNET_HOST", "127.0.0.1"),
            port=int(os.getenv("WORMNET_PORT", "6667")),
            password=os.getenv("WORMNET_PASSWORD", "ELSILRACLIHP"),
            nickname=os.getenv("WORMNET_NICK", "Rbot"),
            username=os.getenv("WORMNET_USERNAME", "rbot"),
            realname=os.getenv("WORMNET_REALNAME", "WormNETBot host bot"),
            channels=channels,
            command_prefix=os.getenv("WORMNET_COMMAND_PREFIX", "!"),
            reply_target=os.getenv("WORMNET_REPLY_TARGET", "channel").lower(),
            reconnect_seconds=float(os.getenv("WORMNET_RECONNECT_SECONDS", "5")),
            log_level=os.getenv("WORMNET_LOG_LEVEL", "INFO").upper(),
            web_base_url=os.getenv("WORMNET_WEB_BASE_URL", "").rstrip("/"),
            game_channel=os.getenv("WORMNET_GAME_CHANNEL", channels[0] if channels else "#AnythingGoes"),
            game_host_ip=os.getenv("WORMNET_GAME_HOST_IP", ""),
            game_location=os.getenv("WORMNET_GAME_LOCATION", "49"),
            game_type=os.getenv("WORMNET_GAME_TYPE", "0"),
            game_bind_host=os.getenv("WORMNET_GAME_BIND_HOST", "0.0.0.0"),
            game_port=int(os.getenv("WORMNET_GAME_PORT", "17011")),
            game_c2_relay=c2,
        )
