import asyncio
import logging
import time
from collections.abc import Callable
from pathlib import Path

from .tr064 import HostFilter, Tr064Error

log = logging.getLogger(__name__)

WAIT_FOR_KEY_S = 600
MIN_INTERVAL_S = 3600
# Verified with prototype/tr064_reconnect_test.py: longer than the 2-minute keep-alive, so the
# inverter notices the dead connection and reconnects with a new session key.
BLOCK_S = 180
CHECK_INTERVAL_S = 30


class ReconnectTrigger:
    """Due when encrypted traffic could not be decrypted for WAIT_FOR_KEY_S, at most once per MIN_INTERVAL_S."""

    def __init__(self, clock: Callable[[], float] = time.monotonic):
        self._clock = clock
        self._undecryptable_since: float | None = None
        self._last_attempt: float | None = None

    def undecryptable_traffic(self) -> None:
        if self._undecryptable_since is None:
            self._undecryptable_since = self._clock()

    def key_valid(self) -> None:
        self._undecryptable_since = None

    def due(self) -> bool:
        now = self._clock()
        if self._undecryptable_since is None or now - self._undecryptable_since < WAIT_FOR_KEY_S:
            return False
        return self._last_attempt is None or now - self._last_attempt >= MIN_INTERVAL_S

    def attempted(self) -> None:
        self._last_attempt = self._clock()


class ForcedReconnect:
    def __init__(self, host_filter: HostFilter, inverter_ip: str, trigger: ReconnectTrigger, block_flag: Path):
        self._filter = host_filter
        self._ip = inverter_ip
        self._trigger = trigger
        self._block_flag = block_flag

    async def recover_from_crash(self) -> None:
        """The app may have been killed while the inverter was blocked; never leave it offline."""
        if self._block_flag.exists():
            log.warning("Previous run ended while %s was blocked, unblocking", self._ip)
            await self._unblock()

    async def run(self) -> None:
        await self.recover_from_crash()
        while True:
            await asyncio.sleep(CHECK_INTERVAL_S)
            if self._trigger.due():
                self._trigger.attempted()
                await self.force()

    async def force(self) -> None:
        log.info("No valid session key for %d min, blocking internet access of %s for %d s "
                 "to make the inverter reconnect", WAIT_FOR_KEY_S // 60, self._ip, BLOCK_S)
        try:
            self._block_flag.touch()
            await self._filter.set_blocked(self._ip, True)
            await asyncio.sleep(BLOCK_S)
        except Tr064Error as e:
            log.warning("Forced reconnect failed: %s", e)
        except Exception as e:
            log.warning("Forced reconnect failed: %s: %s", type(e).__name__, e)
        finally:
            await asyncio.shield(self._unblock())

    async def _unblock(self) -> None:
        for attempt in range(1, 6):
            try:
                await self._filter.set_blocked(self._ip, False)
                self._block_flag.unlink(missing_ok=True)
                log.info("Internet access of %s unblocked", self._ip)
                return
            except Exception as e:
                log.warning("Unblock attempt %d failed: %s", attempt, e)
                await asyncio.sleep(3)
        log.error("Could not unblock %s. Remove the block in the FRITZ!Box UI (Internet > Filter) "
                  "or restart the app", self._ip)
