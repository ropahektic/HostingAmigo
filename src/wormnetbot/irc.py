from __future__ import annotations

from dataclasses import dataclass
import asyncio
import logging


LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class IrcMessage:
    prefix: str | None
    command: str
    params: list[str]

    @property
    def nick(self) -> str | None:
        if not self.prefix:
            return None
        if "!" in self.prefix:
            return self.prefix.split("!", 1)[0]
        return self.prefix


def parse_irc_line(line: str) -> IrcMessage:
    prefix = None
    rest = line.rstrip("\r\n")
    if rest.startswith(":"):
        prefix, rest = rest[1:].split(" ", 1)

    trailing = None
    if " :" in rest:
        rest, trailing = rest.split(" :", 1)

    parts = rest.split()
    command = parts[0].upper()
    params = parts[1:]
    if trailing is not None:
        params.append(trailing)
    return IrcMessage(prefix=prefix, command=command, params=params)


class AsyncIrcClient:
    def __init__(
        self,
        host: str,
        port: int,
        nickname: str,
        username: str,
        realname: str,
        password: str = "",
    ) -> None:
        self.host = host
        self.port = port
        self.nickname = nickname
        self.username = username
        self.realname = realname
        self.password = password
        self.reader: asyncio.StreamReader | None = None
        self.writer: asyncio.StreamWriter | None = None
        self.connected_event = asyncio.Event()
        self.message_handler = None

    async def connect(self) -> None:
        LOGGER.info("Connecting to %s:%s", self.host, self.port)
        self.reader, self.writer = await asyncio.open_connection(self.host, self.port)
        if self.password:
            await self.send_raw(f"PASS {self.password}")
        await self.send_raw(f"NICK {self.nickname}")
        await self.send_raw(f"USER {self.username} hostname servername :{self.realname}")

    async def run(self) -> None:
        assert self.reader is not None
        while True:
            data = await self.reader.readline()
            if not data:
                raise ConnectionError("IRC connection closed")
            line = data.decode("utf-8", errors="replace").rstrip("\r\n")
            LOGGER.debug("< %s", line)
            message = parse_irc_line(line)
            if message.command == "PING" and message.params:
                await self.send_raw(f"PONG :{message.params[-1]}")
                continue
            if message.command == "001":
                self.connected_event.set()
            if self.message_handler is not None:
                await self.message_handler(message)

    async def wait_until_ready(self) -> None:
        await self.connected_event.wait()

    async def send_raw(self, line: str) -> None:
        assert self.writer is not None
        LOGGER.debug("> %s", line)
        self.writer.write((line + "\r\n").encode("utf-8"))
        await self.writer.drain()

    async def join(self, channel: str) -> None:
        await self.send_raw(f"JOIN {channel}")

    async def privmsg(self, target: str, text: str) -> None:
        await self.send_raw(f"PRIVMSG {target} :{text}")

    async def notice(self, target: str, text: str) -> None:
        await self.send_raw(f"NOTICE {target} :{text}")

    async def quit(self, reason: str = "Bye") -> None:
        if self.writer is None:
            return
        await self.send_raw(f"QUIT :{reason}")
        self.writer.close()
        await self.writer.wait_closed()
