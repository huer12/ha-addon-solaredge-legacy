import asyncio
import json
import logging
import time
from collections.abc import Callable
from datetime import UTC, date, datetime
from pathlib import Path

import aiomqtt

from . import discovery as d
from .optimizer_check import UNDERPERFORMING_PERCENT, evaluate

log = logging.getLogger(__name__)

# Optimizers send their last reports a few minutes after the inverter stops producing.
OPTIMIZER_CHECK_DELAY_S = 600


class Publisher:
    """Collects state from the sync decoder callbacks; flush() publishes what changed."""

    def __init__(self, version: str, optimizer_details: bool, data_dir: Path | None = None,
                 today: Callable[[], date] = date.today, clock: Callable[[], float] = time.monotonic):
        self._version = version
        self._details = optimizer_details
        self._device_info_file = data_dir / "device_info.json" if data_dir else None
        self._energy_today_file = data_dir / "energy_today.json" if data_dir else None
        self._optimizers_file = data_dir / "optimizers.json" if data_dir else None
        self._today = today
        self._clock = clock
        self._energy_today_day, self._energy_today = self._load_energy_today()
        self._client: aiomqtt.Client | None = None
        self._flush_lock = asyncio.Lock()
        self._sent: dict[str, str] = {}
        self._outbox: dict[str, str] = {}
        self._optimizers: set[str] = self._load_optimizers()
        self._optimizer_energy: dict[str, tuple[str, int]] = {}
        self._last_mode: int | None = None
        self._check_at: float | None = None
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

    def _load_optimizers(self) -> set[str]:
        try:
            return set(json.loads(self._optimizers_file.read_text()))
        except (AttributeError, OSError, ValueError, TypeError):
            return set()

    def _save_optimizers(self) -> None:
        if self._optimizers_file:
            self._optimizers_file.write_text(json.dumps(sorted(self._optimizers)))

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
        mode = state["mode"]
        if self._last_mode in d.PRODUCING_MODES and mode not in d.PRODUCING_MODES:
            self._check_at = self._clock() + OPTIMIZER_CHECK_DELAY_S
        self._last_mode = mode
        self._queue(d.INVERTER_STATE_TOPIC, state)
        self._diagnostics["last_telemetry"] = datetime.now(UTC).isoformat(timespec="seconds")
        self._queue_diagnostics()

    def _handle_optimizer(self, t: dict) -> None:
        opt_id = t["id"]
        if opt_id not in self._optimizers:
            self._optimizers.add(opt_id)
            log.info("New optimizer %s (%d known)", opt_id, len(self._optimizers))
            self._save_optimizers()
            self._queue(d.discovery_topic(d.optimizer_device_id(opt_id)),
                        d.optimizer_discovery(self._version, opt_id, self._details))
        self._optimizer_energy[opt_id] = (self._today().isoformat(), t["e_day_wh"])
        self._queue(d.optimizer_state_topic(opt_id), d.optimizer_state(t, self._details))

    def _run_due_optimizer_check(self) -> None:
        if self._check_at is None or self._clock() < self._check_at:
            return
        self._check_at = None
        day = self._today().isoformat()
        energy = {opt_id: wh for opt_id, (report_day, wh) in self._optimizer_energy.items() if report_day == day}
        result = evaluate(energy, self._optimizers)
        if result is None:
            log.info("Optimizer check skipped: too little production today")
            return
        for opt_id, pct in result.relative_yield.items():
            self._queue(d.optimizer_daily_topic(opt_id), {"relative_yield": pct, "date": day})
        self._queue(d.OPTIMIZER_CHECK_TOPIC, {
            "underperforming_optimizers": len(result.underperforming),
            "missing_optimizers": len(result.missing),
            "underperforming": result.underperforming,
            "missing": result.missing,
            "date": day,
        })
        if result.underperforming or result.missing:
            log.warning("Optimizer check: below %d %% of the median: %s; missing today: %s",
                        UNDERPERFORMING_PERCENT,
                        ", ".join("%s (%.0f %%)" % kv for kv in result.underperforming.items()) or "none",
                        ", ".join(result.missing) or "none")
        else:
            log.info("Optimizer check: all %d optimizers within %d %% of the median",
                     len(result.relative_yield), 100 - UNDERPERFORMING_PERCENT)

    def _handle_device_info(self, t: dict) -> None:
        model, serial = d.device_model_and_serial(t["strings"])
        log.debug("Device info %s", t["strings"])
        if model and (model, serial) != (self._model, self._serial):
            log.info("Inverter %s, serial %s", model, serial)
            self._model, self._serial = model, serial
            self._save_device_info()
            self._queue_inverter_discovery()

    async def flush(self) -> None:
        self._run_due_optimizer_check()
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
