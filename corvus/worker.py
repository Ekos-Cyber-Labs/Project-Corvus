"""Placeholder worker loop with clean SIGTERM shutdown."""

import asyncio
import signal


async def run() -> None:
    """Idle until SIGTERM or SIGINT is received."""
    stop = asyncio.Event()

    def _handle_signal(*_args: object) -> None:
        stop.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, _handle_signal)
        except NotImplementedError:
            signal.signal(sig, lambda *_a: stop.set())
    await stop.wait()


def main() -> None:
    """Entry point for the worker container."""
    asyncio.run(run())


if __name__ == "__main__":
    main()
