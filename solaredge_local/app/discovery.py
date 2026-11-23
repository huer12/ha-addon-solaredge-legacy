from dataclasses import dataclass, field

BASE = "solaredge_local"
STATUS_TOPIC = BASE + "/status"
CAPTURE_TOPIC = BASE + "/capture"
INVERTER_STATE_TOPIC = BASE + "/inverter/state"
DIAGNOSTICS_TOPIC = BASE + "/inverter/diagnostics"
OPTIMIZER_CHECK_TOPIC = BASE + "/inverter/optimizer_check"
INVERTER_DEVICE_ID = "solaredge_local_inverter"
DISCOVERY_PREFIX = "homeassistant"

TELEMETRY_AVAILABILITY = {
    "availability": [{"topic": STATUS_TOPIC}, {"topic": CAPTURE_TOPIC}],
    "availability_mode": "all",
}
BRIDGE_AVAILABILITY = {"availability": [{"topic": STATUS_TOPIC}]}

# SunSpec I_STATUS numbering; observed on CPU 2.x: 2 at night, 3 at dawn/dusk, 4 producing, 5 briefly at start-up.
MODE_TEXT = {
    1: "Off",
    2: "Night",
    3: "Wake-up",
    4: "Producing",
    5: "Producing (throttled)",
    6: "Shutting down",
    7: "Fault",
    8: "Standby",
}
PRODUCING_MODES = (4, 5)


@dataclass(frozen=True)
class Sensor:
    key: str
    name: str
    device_class: str | None = None
    unit: str | None = None
    state_class: str | None = "measurement"
    precision: int | None = None
    enabled: bool = True
    diagnostic: bool = False
    platform: str = "sensor"
    extra: dict = field(default_factory=dict)


def _phases(key, name, **kw):
    return [Sensor("%s_l%d" % (key, n), "%s L%d" % (name, n), **kw) for n in (1, 2, 3)]


INVERTER_SENSORS = [
    Sensor("ac_power", "AC power", "power", "W", precision=0),
    *_phases("ac_power", "AC power", device_class="power", unit="W", precision=0),
    *_phases("ac_voltage", "AC voltage", device_class="voltage", unit="V", precision=1),
    *_phases("ac_current", "AC current", device_class="current", unit="A", precision=2),
    Sensor("ac_frequency", "AC frequency", "frequency", "Hz", precision=2),
    Sensor("dc_voltage", "DC voltage", "voltage", "V", precision=1),
    Sensor("temperature", "Temperature", "temperature", "°C", precision=1),
    Sensor("energy_today", "Energy today", "energy", "Wh", "total_increasing", precision=0),
    Sensor("energy_total", "Energy total", "energy", "kWh", "total_increasing", precision=2),
    Sensor("status", "Status", state_class=None),
    Sensor("mode", "Mode", state_class=None, diagnostic=True),
]

DIAGNOSTIC_SENSORS = [
    Sensor("capture_state", "Capture", state_class=None, diagnostic=True),
    Sensor("session_key_valid", "Session key", "connectivity", state_class=None, diagnostic=True,
           platform="binary_sensor",
           extra={"value_template": "{{ 'ON' if value_json.session_key_valid else 'OFF' }}"}),
    Sensor("last_telemetry", "Last telemetry", "timestamp", state_class=None, diagnostic=True),
]

OPTIMIZER_CHECK_SENSORS = [
    Sensor("underperforming_optimizers", "Underperforming optimizers", state_class="measurement",
           extra={"json_attributes_topic": OPTIMIZER_CHECK_TOPIC,
                  "json_attributes_template": "{{ {'optimizers': value_json.underperforming} | tojson }}"}),
    Sensor("missing_optimizers", "Missing optimizers", state_class="measurement",
           extra={"json_attributes_topic": OPTIMIZER_CHECK_TOPIC,
                  "json_attributes_template": "{{ {'optimizers': value_json.missing} | tojson }}"}),
]

OPTIMIZER_DAILY_SENSORS = [
    Sensor("relative_yield", "Relative yield", unit="%", precision=0),
]

OPTIMIZER_SENSORS = [
    Sensor("power", "Power", "power", "W", precision=1),
    Sensor("energy_today", "Energy today", "energy", "Wh", "total_increasing", precision=0),
]

OPTIMIZER_DETAIL_SENSORS = [
    Sensor("v_in", "Input voltage", "voltage", "V", precision=1, enabled=False),
    Sensor("v_out", "Output voltage", "voltage", "V", precision=1, enabled=False),
    Sensor("i_in", "Input current", "current", "A", precision=2, enabled=False),
    Sensor("temperature", "Temperature", "temperature", "°C", precision=0, enabled=False),
]


def optimizer_state_topic(opt_id: str) -> str:
    return "%s/optimizer/%s/state" % (BASE, opt_id)


def optimizer_daily_topic(opt_id: str) -> str:
    return "%s/optimizer/%s/daily" % (BASE, opt_id)


def discovery_topic(device_id: str) -> str:
    return "%s/device/%s/config" % (DISCOVERY_PREFIX, device_id)


def _component(unique_prefix: str, s: Sensor, state_topic: str, availability: dict) -> dict:
    c = {
        "p": s.platform,
        "unique_id": "%s_%s" % (unique_prefix, s.key),
        "name": s.name,
        "state_topic": state_topic,
        "value_template": "{{ value_json.%s }}" % s.key,
        **availability,
    }
    if s.device_class:
        c["device_class"] = s.device_class
    if s.unit:
        c["unit_of_measurement"] = s.unit
    if s.state_class:
        c["state_class"] = s.state_class
    if s.precision is not None:
        c["suggested_display_precision"] = s.precision
    if not s.enabled:
        c["enabled_by_default"] = False
    if s.diagnostic:
        c["entity_category"] = "diagnostic"
    c.update(s.extra)
    return c


def _origin(version: str) -> dict:
    return {"name": "SolarEdge Local", "sw": version, "url": "https://github.com/huer12/ha-addon-solaredge-legacy"}


def inverter_discovery(version: str, model: str | None, serial: str | None) -> dict:
    device = {"identifiers": [INVERTER_DEVICE_ID], "name": "SolarEdge Inverter", "manufacturer": "SolarEdge"}
    if model:
        device["model"] = model
    if serial:
        device["serial_number"] = serial
    cmps = {s.key: _component(INVERTER_DEVICE_ID, s, INVERTER_STATE_TOPIC, TELEMETRY_AVAILABILITY)
            for s in INVERTER_SENSORS}
    cmps.update({s.key: _component(INVERTER_DEVICE_ID, s, DIAGNOSTICS_TOPIC, BRIDGE_AVAILABILITY)
                 for s in DIAGNOSTIC_SENSORS})
    cmps.update({s.key: _component(INVERTER_DEVICE_ID, s, OPTIMIZER_CHECK_TOPIC, BRIDGE_AVAILABILITY)
                 for s in OPTIMIZER_CHECK_SENSORS})
    return {"device": device, "origin": _origin(version), "components": cmps}


def optimizer_device_id(opt_id: str) -> str:
    return "solaredge_local_optimizer_%s" % opt_id.lower()


def optimizer_discovery(version: str, opt_id: str, details: bool) -> dict:
    device_id = optimizer_device_id(opt_id)
    device = {"identifiers": [device_id], "name": "Optimizer %s" % opt_id, "manufacturer": "SolarEdge",
              "model": "Power optimizer", "serial_number": opt_id, "via_device": INVERTER_DEVICE_ID}
    sensors = OPTIMIZER_SENSORS + (OPTIMIZER_DETAIL_SENSORS if details else [])
    cmps = {s.key: _component(device_id, s, optimizer_state_topic(opt_id), TELEMETRY_AVAILABILITY)
            for s in sensors}
    cmps.update({s.key: _component(device_id, s, optimizer_daily_topic(opt_id), BRIDGE_AVAILABILITY)
                 for s in OPTIMIZER_DAILY_SENSORS})
    return {"device": device, "origin": _origin(version), "components": cmps}


def _in_range(value, low, high):
    return value if value is not None and low <= value <= high else None


def _round(value, digits):
    return None if value is None else round(value, digits)


def inverter_state(t: dict) -> dict:
    """Map a parsed 3-phase block to state values; Vac/Iac/Freq are garbage at night and right after boot."""
    mode = t.get("Mode")
    state = {"mode": mode, "status": MODE_TEXT.get(mode, "Unknown (%s)" % mode)}
    powers = []
    for n in (1, 2, 3):
        voltage = _in_range(t.get("Vac%d" % n), 150, 300)
        current = _in_range(t.get("Iac%d" % n), 0, 100) if voltage is not None else None
        power = _in_range(t.get("Pactive%d" % n), -1000, 15000)
        state["ac_voltage_l%d" % n] = _round(voltage, 1)
        state["ac_current_l%d" % n] = _round(current, 2)
        state["ac_power_l%d" % n] = _round(power, 0)
        powers.append(power)
    state["ac_power"] = None if None in powers else round(sum(powers), 0)
    state["ac_frequency"] = _round(_in_range(t.get("Freq1"), 45, 55), 2)
    state["dc_voltage"] = _round(_in_range(t.get("Vdc"), 0, 1000), 1)
    temperature = _in_range(t.get("Temp"), -40, 120)
    if temperature == 0 and mode not in PRODUCING_MODES:
        temperature = None  # the inverter reports exactly 0.0 °C while it is not producing
    state["temperature"] = _round(temperature, 1)
    state["energy_today"] = _round(_in_range(t.get("EdayAC"), 0, 200_000), 0)
    etotal = t.get("Etotal_i")
    state["energy_total"] = round(etotal / 1000, 3) if etotal else None
    return state


def optimizer_state(t: dict, details: bool) -> dict:
    state = {"power": round(t["v_in"] * t["i_in"], 1), "energy_today": t["e_day_wh"]}
    if details:
        state.update({"v_in": t["v_in"], "v_out": t["v_out"], "i_in": t["i_in"], "temperature": t["temperature"]})
    return state


def device_model_and_serial(strings: list[str]) -> tuple[str | None, str | None]:
    """0x0017 device info: 'SolarEdge', model, serial, sub-devices..."""
    if len(strings) >= 3 and strings[0] == "SolarEdge":
        return strings[1], strings[2]
    return None, None
