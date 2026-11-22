import ipaddress
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path

import aiohttp

SUPERVISOR_MQTT_URL = "http://supervisor/services/mqtt"


class ConfigError(Exception):
    pass


@dataclass(frozen=True)
class Options:
    fritzbox_host: str
    fritzbox_user: str
    fritzbox_password: str
    inverter_ip: str
    inverter_key: bytes
    capture_interface: str
    optimizer_details: bool
    force_reconnect: bool
    log_level: str


@dataclass(frozen=True)
class MqttSettings:
    host: str
    port: int
    username: str | None
    password: str | None


def _required(raw: dict, name: str) -> str:
    value = str(raw.get(name) or "").strip()
    if not value:
        raise ConfigError("Option '%s' is missing" % name)
    return value


def parse_inverter_key(value: str) -> bytes:
    cleaned = re.sub(r"[\s:-]", "", value)
    if not re.fullmatch(r"[0-9a-fA-F]{32}", cleaned):
        raise ConfigError("Option 'inverter_key' must be 32 hex characters (16 bytes), got %d characters"
                          % len(cleaned))
    return bytes.fromhex(cleaned)


def parse_options(raw: dict) -> Options:
    inverter_ip = _required(raw, "inverter_ip")
    try:
        ipaddress.IPv4Address(inverter_ip)
    except ValueError:
        raise ConfigError("Option 'inverter_ip' is not a valid IPv4 address: %s" % inverter_ip) from None
    return Options(
        fritzbox_host=str(raw.get("fritzbox_host") or "fritz.box").strip(),
        fritzbox_user=_required(raw, "fritzbox_user"),
        fritzbox_password=_required(raw, "fritzbox_password"),
        inverter_ip=inverter_ip,
        inverter_key=parse_inverter_key(_required(raw, "inverter_key")),
        capture_interface=str(raw.get("capture_interface") or "1-lan").strip(),
        optimizer_details=bool(raw.get("optimizer_details", False)),
        force_reconnect=bool(raw.get("force_reconnect", True)),
        log_level=str(raw.get("log_level") or "info").lower(),
    )


def load_options(path: Path) -> Options:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise ConfigError("Options file %s not found" % path) from None
    return parse_options(raw)


async def load_mqtt_settings() -> MqttSettings:
    """Supervisor service discovery inside HA; MQTT_* environment variables for local runs."""
    token = os.environ.get("SUPERVISOR_TOKEN")
    if not token:
        return MqttSettings(
            host=os.environ.get("MQTT_HOST", "localhost"),
            port=int(os.environ.get("MQTT_PORT", "1883")),
            username=os.environ.get("MQTT_USER") or None,
            password=os.environ.get("MQTT_PASSWORD") or None,
        )
    async with aiohttp.ClientSession() as session:
        async with session.get(SUPERVISOR_MQTT_URL, headers={"Authorization": "Bearer " + token}) as resp:
            if resp.status != 200:
                raise ConfigError("MQTT service not available (HTTP %d). Is the Mosquitto broker app "
                                  "installed and running?" % resp.status)
            data = (await resp.json())["data"]
    return MqttSettings(data["host"], int(data["port"]), data.get("username"), data.get("password"))
