from __future__ import annotations

import asyncio
import contextlib
import logging
from typing import Awaitable, Callable

from .config import BotConfig
from .game_api import GameAdvertiser, HostedGame
from .game_host import GameSession
from .irc import AsyncIrcClient, IrcMessage


LOGGER = logging.getLogger(__name__)


CommandHandler = Callable[[str | None, str, bool, list[str]], Awaitable[None]]


class WormNetBot:
    def __init__(self, config: BotConfig) -> None:
        self.config = config
        self.irc = AsyncIrcClient(
            host=config.host,
            port=config.port,
            nickname=config.nickname,
            username=config.username,
            realname=config.realname,
            password=config.password,
        )
        self.irc.message_handler = self._handle_message
        self.game_advertiser = GameAdvertiser(config)
        self.active_game: HostedGame | None = None
        self.active_session: GameSession | None = None

    async def _reply(self, target: str, text: str, *, private: bool) -> None:
        if private:
            await self.irc.privmsg(target, text)
        else:
            await self.irc.notice(target, text)

    async def _handle_session_started(self) -> None:
        hosted = self.active_game
        session = self.active_session
        if hosted is None or session is None:
            return
        try:
            await asyncio.to_thread(self.game_advertiser.close_game, hosted.game_id)
        except Exception as exc:
            LOGGER.warning("Auto-close on game start failed: %s", exc)
            return
        if self.active_game is hosted and self.active_session is session:
            self.active_game = None
        LOGGER.info("Closed game advertisement id=%s because the game started", hosted.game_id)

    async def _handle_session_ended(self) -> None:
        session = self.active_session
        if session is None:
            return
        winner = session.winner_summary()
        self.active_session = None
        if winner is not None:
            LOGGER.info("Detected winner from endgame frames: %s", winner)
        LOGGER.info("Cleared finished game session after all players left")

    async def run_forever(self) -> None:
        while True:
            runner: asyncio.Task | None = None
            try:
                self.irc = AsyncIrcClient(
                    host=self.config.host,
                    port=self.config.port,
                    nickname=self.config.nickname,
                    username=self.config.username,
                    realname=self.config.realname,
                    password=self.config.password,
                )
                self.irc.message_handler = self._handle_message
                await self.irc.connect()
                runner = asyncio.create_task(self.irc.run())
                await self.irc.wait_until_ready()
                LOGGER.info("Connected as %s", self.config.nickname)
                for channel in self.config.channels:
                    await self.irc.join(channel)
                await runner
            except Exception as exc:
                LOGGER.warning("Bot disconnected: %s", exc)
                if runner is not None:
                    runner.cancel()
                    with contextlib.suppress(Exception):
                        await runner
                await asyncio.sleep(self.config.reconnect_seconds)

    async def _handle_message(self, message: IrcMessage) -> None:
        if message.command == "PRIVMSG":
            await self._handle_privmsg(message)
        elif message.command == "JOIN" and message.nick == self.config.nickname:
            LOGGER.info("Joined %s", message.params[0] if message.params else "<unknown>")

    async def _handle_privmsg(self, message: IrcMessage) -> None:
        if len(message.params) != 2:
            return

        target, text = message.params
        sender = message.nick
        is_private = target.lower() == self.config.nickname.lower()
        if not text.startswith(self.config.command_prefix):
            return

        command_text = text[len(self.config.command_prefix) :].strip()
        if not command_text:
            return
        parts = command_text.split()
        command = parts[0].lower()
        args = parts[1:]

        reply_private = sender is not None and (is_private or self.config.reply_target == "private")
        reply_target = sender if reply_private and sender is not None else target

        handlers = {
            "help": self._cmd_help,
            "ping": self._cmd_ping,
            "echo": self._cmd_echo,
            "jost": self._cmd_jost,
            "color": self._cmd_color,
            "ready": self._cmd_ready,
            "start": self._cmd_start,
            "close": self._cmd_close,
            "status": self._cmd_status,
        }
        handler = handlers.get(command)
        if handler is None:
            await self._reply(reply_target, f"Unknown command: {command}", private=reply_private)
            return
        await handler(sender, reply_target, reply_private, args)

    async def _cmd_help(self, sender: str | None, reply_target: str, reply_private: bool, args: list[str]) -> None:
        await self._reply(
            reply_target,
            "Commands: !help, !ping, !echo <text>, !jost <scheme> [game name], !color <team> <color 1-6>, !ready, !start, !close, !status",
            private=reply_private,
        )

    async def _cmd_ping(self, sender: str | None, reply_target: str, reply_private: bool, args: list[str]) -> None:
        await self._reply(reply_target, "pong", private=reply_private)

    async def _cmd_echo(self, sender: str | None, reply_target: str, reply_private: bool, args: list[str]) -> None:
        if not args:
            await self._reply(reply_target, "Usage: !echo <text>", private=reply_private)
            return
        await self._reply(reply_target, " ".join(args), private=reply_private)

    async def _cmd_jost(self, sender: str | None, reply_target: str, reply_private: bool, args: list[str]) -> None:
        if not args:
            await self._reply(reply_target, "Usage: !jost <scheme> [game name]", private=reply_private)
            return
        if self.active_game is not None:
            await self._reply(
                reply_target,
                f"A game advertisement is already active (id {self.active_game.game_id}, scheme {self.active_game.scheme}). Use !close first.",
                private=reply_private,
            )
            return
        scheme = args[0]
        game_name = " ".join(args[1:]).strip() or None
        session = GameSession(self.config, scheme)
        session.on_game_started = self._handle_session_started
        session.on_game_ended = self._handle_session_ended
        try:
            await session.start()
            hosted = await asyncio.to_thread(self.game_advertiser.create_game, sender, scheme, game_name)
        except Exception as exc:
            with contextlib.suppress(Exception):
                await session.stop()
            LOGGER.warning("Jost command failed: %s", exc)
            await self._reply(reply_target, f"Jost failed: {exc}", private=reply_private)
            return
        self.active_game = hosted
        self.active_session = session
        session_status = session.status()
        await self._reply(
            reply_target,
            f"Game advertisement created: id={hosted.game_id} name='{hosted.name}'. WA host listener is live on {session_status.bind_host}:{session_status.port} using scheme {scheme}.",
            private=reply_private,
        )

    async def _cmd_close(self, sender: str | None, reply_target: str, reply_private: bool, args: list[str]) -> None:
        if self.active_game is None:
            await self._reply(reply_target, "No active game advertisement to close.", private=reply_private)
            return
        closing = self.active_game
        closing_session = self.active_session
        try:
            await asyncio.to_thread(self.game_advertiser.close_game, closing.game_id)
        except Exception as exc:
            LOGGER.warning("Close command failed: %s", exc)
            await self._reply(reply_target, f"Close failed: {exc}", private=reply_private)
            return
        if closing_session is not None:
            with contextlib.suppress(Exception):
                await closing_session.stop()
        self.active_game = None
        self.active_session = None
        await self._reply(reply_target, f"Closed game advertisement id={closing.game_id}.", private=reply_private)

    async def _cmd_ready(self, sender: str | None, reply_target: str, reply_private: bool, args: list[str]) -> None:
        if self.active_session is None:
            await self._reply(reply_target, "No active hosted lobby to ready.", private=reply_private)
            return
        try:
            await self.active_session.set_host_ready(True)
        except Exception as exc:
            LOGGER.warning("Ready command failed: %s", exc)
            await self._reply(reply_target, f"Ready failed: {exc}", private=reply_private)
            return
        await self._reply(reply_target, "Rbot marked ready in the lobby.", private=reply_private)

    async def _cmd_color(self, sender: str | None, reply_target: str, reply_private: bool, args: list[str]) -> None:
        if self.active_session is None:
            await self._reply(reply_target, "No active hosted lobby to recolor.", private=reply_private)
            return
        if len(args) != 2:
            await self._reply(reply_target, "Usage: !color <team> <color 1-6>", private=reply_private)
            return
        try:
            team_index = int(args[0])
            color_index = int(args[1])
        except ValueError:
            await self._reply(reply_target, "Usage: !color <team> <color 1-6>", private=reply_private)
            return
        if color_index < 1 or color_index > 6:
            await self._reply(reply_target, "Color must be between 1 and 6.", private=reply_private)
            return
        color = color_index - 1
        try:
            team = await self.active_session.set_team_color(team_index, color)
        except Exception as exc:
            LOGGER.warning("Color command failed: %s", exc)
            await self._reply(reply_target, f"Color failed: {exc}", private=reply_private)
            return
        await self._reply(
            reply_target,
            f"Set team {team_index} color to {color_index}.",
            private=reply_private,
        )

    async def _cmd_start(self, sender: str | None, reply_target: str, reply_private: bool, args: list[str]) -> None:
        if self.active_session is None:
            await self._reply(reply_target, "No active hosted lobby to start.", private=reply_private)
            return
        try:
            await self.active_session.start_game()
        except Exception as exc:
            LOGGER.warning("Start command failed: %s", exc)
            await self._reply(reply_target, f"Start failed: {exc}", private=reply_private)
            return
        await self._reply(reply_target, "Sent start-game packet to connected players.", private=reply_private)

    async def _cmd_status(self, sender: str | None, reply_target: str, reply_private: bool, args: list[str]) -> None:
        if self.active_game is None:
            await self._reply(reply_target, "Status: connected, no active game advertisement.", private=reply_private)
        else:
            session_note = ""
            if self.active_session is not None:
                session = self.active_session.status()
                session_note = (
                    f" Listener={session.bind_host}:{session.port} "
                    f"joins={session.join_attempts} players={session.connected_players} schemeId={session.scheme_id}."
                )
            await self._reply(
                reply_target,
                f"Status: connected, game advertisement active id={self.active_game.game_id} scheme='{self.active_game.scheme}' name='{self.active_game.name}'.{session_note}",
                private=reply_private,
            )
