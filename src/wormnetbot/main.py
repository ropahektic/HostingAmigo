from __future__ import annotations

import asyncio
import logging

from .bot import WormNetBot
from .config import BotConfig


def configure_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level, logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


async def _async_main() -> None:
    config = BotConfig.from_env()
    configure_logging(config.log_level)
    bot = WormNetBot(config)
    await bot.run_forever()


def main() -> None:
    asyncio.run(_async_main())


if __name__ == "__main__":
    main()
