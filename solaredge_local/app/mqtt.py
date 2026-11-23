import asyncio
import json
import logging
from collections.abc import Callable
from datetime import UTC, date, datetime
from pathlib import Path

import aiomqtt

from . import discovery as d

log = logging.getLogger(__name__)


class Publisher:
    """Collects state from the sync decoder callbacks; flush() publishes what changed."""

    def __init__(self, version: str, optimizer_details: bool, device_info_file: Path | None = None,
                 energy_today_file: Path | None = None, today: Callable[[], date] = date.today):
        self._version = version
        self._details = optimizer_details
        self._device_info_file = device_info_file
        self._energy_today_file = energy_today_file
        self._today = today
        self._energy_today_day, self._energy_today = self._load_energy_today()
        self._client: aiomqtt.Client | None = None
        self._flush_lock = asyncio.Lock()
        self._sent: dict[str, str] = {}
        self._outbox: dict[str, str] = {}
        self._optimizers: set[str] = set()
        self._model, self._serial = self._load_device_info()
        self._energy_total: float | None = None
        self._diagnostics = {"capture_state": "starting", "session_key_valid": False, "last_telemetry": None}

    def _load_device_info(self) -> tuple[str | None, str | None]:
        try:
            info = json.loads(self._device_info_file.read_text())
            return info.get("model"), info.get("serial")
        except (AttributeError, OSError, ValueError):
            return None, None

    def _save_device_info(self) -> None:
        if self._device_info_file:
            self._device_info_file.write_text(json.dumps({"model": self._model, "serial": self._serial}))

    def _load_energy_today(self) -> tuple[str | None, float | None]:
        try:
            saved = json.loads(self._energy_today_file.read_text())
            return saved["day"], saved["wh"]
        except (AttributeError, OSError, ValueError, KeyError):
            return None, None

    def _hold_energy_today(self, wh: float | None) -> float | None:
        """The inverter resets its daily counter when it stops producing in the evening; keep the day's value."""
        if wh is None:
            return self._energy_today if self._energy_today_day == self._today().isoformat() else None
        day = self._today().isoformat()
        if day == self._energy_today_day and self._energy_today is not None and wh < self._energy_today:
            return self._energy_today
        if (day, wh) != (self._energy_today_day, self._energy_today):
            self._energy_today_day, self._energy_today = day, wh
            if self._energy_today_file:
                self._energy_today_file.write_text(json.dumps({"day": day, "wh": wh}))
        return wh

    def _queue(self, topic: str, payload) -> None:
        self._outbox[topic] = payload if isinstance(payload, str) else json.dumps(payload)

    def _queue_inverter_discovery(self) -> None:
        self._queue(d.discovery_topic(d.INVERTER_DEVICE_ID),
                    d.inverter_discovery(self._version, self._model, self._serial))

    def _queue_diagnostics(self) -> None:
        self._queue(d.DIAGNOSTICS_TOPIC, self._diagnostics)

    async def attach(self, client: aiomqtt.Client) -> None:
        """Called after every (re)connect to the broker: republish everything."""
        self._client = client
        self._sent.clear()
        self._queue(d.STATUS_TOPIC, "online")
        self._queue_inverter_discovery()
        for opt_id in self._optimizers:
            self._queue(d.discovery_topic(d.optimizer_device_id(opt_id)),
                        d.optimizer_discovery(self._version, opt_id, self._details))
        self._queue_diagnostics()
        await self.flush()

    def detach(self) -> None:
        self._client = None

    def set_capture_state(self, state: str) -> None:
        self._diagnostics["capture_state"] = state
        self._queue(d.CAPTURE_TOPIC, "online" if state == "connected" else "offline")
        self._queue_diagnostics()

    def set_session_key_valid(self, valid: bool) -> None:
        self._diagnostics["session_key_valid"] = valid
        self._queue_diagnostics()

    def handle_telemetry(self, t: dict) -> None:
        kind = t["kind"]
        if kind == "inverter_3ph":
            self._handle_inverter(t)
        elif kind == "optimizer":
            self._handle_optimizer(t)
        elif kind == "device_info":
            self._handle_device_info(t)
        else:
            log.debug("Not published: %s", t)

    def _handle_inverter(self, t: dict) -> None:
        if not self._serial:
            self._serial = t["id"]
            self._save_device_info()
            self._queue_inverter_discovery()
        state = d.inverter_state(t)
        total = state["energy_total"]
        if total is not None and self._energy_total is not None and total < self._energy_total:
            # A decreasing total_increasing value counts as a meter reset in the energy dashboard.
            log.warning("Ignoring lifetime energy %.3f kWh, lower than last value %.3f kWh", total, self._energy_total)
            state["energy_total"] = self._energy_total
        elif total is not None:
            self._energy_total = total
        state["energy_today"] = self._hold_energy_today(state["energy_today"])
        self._queue(d.INVERTER_STATE_TOPIC, state)
        self._diagnostics["last_telemetry"] = datetime.now(UTC).isoformat(timespec="seconds")
        self._queue_diagnostics()

    def _handle_optimizer(self, t: dict) -> None:
        opt_id = t["id"]
        if opt_id not in self._optimizers:
            self._optimizers.add(opt_id)
            log.info("New optimizer %s (%d known)", opt_id, len(self._optimizers))
            self._queue(d.discovery_topic(d.optimizer_device_id(opt_id)),
                        d.optimizer_discovery(self._version, opt_id, self._details))
        self._queue(d.optimizer_state_topic(opt_id), d.optimizer_state(t, self._details))

    def _handle_device_info(self, t: dict) -> None:
        model, serial = d.device_model_and_serial(t["strings"])
        log.debug("Device info %s", t["strings"])
        if model and (model, serial) != (self._model, self._serial):
            log.info("Inverter %s, serial %s", model, serial)
            self._model, self._serial = model, serial
            self._save_device_info()
            self._queue_inverter_discovery()

    async def flush(self) -> None:
        async with self._flush_lock:
            while self._client and self._outbox:
                topic, payload = next(iter(self._outbox.items()))
                if self._sent.get(topic) != payload:
                    try:
                        await self._client.publish(topic, payload, qos=1, retain=True)
                    except aiomqtt.MqttError as e:
                        log.debug("Publish to %s failed, kept for the next connection: %s", topic, e)
                        return
                    self._sent[topic] = payload
                if self._outbox.get(topic) == payload:
                    del self._outbox[topic]
