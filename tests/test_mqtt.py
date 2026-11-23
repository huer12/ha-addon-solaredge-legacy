import json
from datetime import date

import pytest

from app import discovery as d
from app.mqtt import Publisher
from app.solaredge import parse0500
from helpers import device_info_block, inverter3_block, optimizer_block


class FakeClient:
    def __init__(self):
        self.messages = []

    async def publish(self, topic, payload, qos=0, retain=False):
        self.messages.append((topic, json.loads(payload) if payload.startswith("{") else payload))

    def topics(self):
        return [t for t, _ in self.messages]

    def last(self, topic):
        return [p for t, p in self.messages if t == topic][-1]


def producing_block(**overrides):
    values = dict(Mode=4, Vac1=238.0, Vac2=237.5, Vac3=239.0, Iac1=0.9, Iac2=0.9, Iac3=0.9, Freq1=50.0,
                  Pactive1=210.0, Pactive2=220.0, Pactive3=205.0, Vdc=751.0, Temp=28.0, EdayAC=1500.0,
                  Etotal_i=129_340_000)
    values.update(overrides)
    return next(parse0500(inverter3_block(0x7F012345, **values)))


async def test_attach_publishes_status_inverter_discovery_and_diagnostics():
    client, pub = FakeClient(), Publisher("0.1.0", optimizer_details=False)

    await pub.attach(client)

    assert d.STATUS_TOPIC in client.topics()
    config = client.last(d.discovery_topic(d.INVERTER_DEVICE_ID))
    assert config["components"]["energy_total"]["state_class"] == "total_increasing"
    assert config["components"]["session_key_valid"]["p"] == "binary_sensor"


async def test_inverter_state_sums_phases_and_converts_energy_to_kwh():
    client, pub = FakeClient(), Publisher("0.1.0", optimizer_details=False)
    await pub.attach(client)

    pub.handle_telemetry(producing_block())
    await pub.flush()

    state = client.last(d.INVERTER_STATE_TOPIC)
    assert state["ac_power"] == 635
    assert state["energy_total"] == 129_340.0
    assert state["status"] == "Producing"


def test_garbage_night_values_become_none():
    state = d.inverter_state(producing_block(Mode=2, Vac1=2.7e6, Freq1=-5279.0))

    assert state["ac_voltage_l1"] is None
    assert state["ac_current_l1"] is None
    assert state["ac_frequency"] is None
    assert state["status"] == "Night"


@pytest.mark.parametrize("mode, text", [(3, "Wake-up"), (4, "Producing"), (5, "Producing (throttled)"),
                                        (42, "Unknown (42)")])
def test_mode_text(mode, text):
    assert d.inverter_state(producing_block(Mode=mode))["status"] == text


@pytest.mark.parametrize("mode, temp, expected", [(2, 0.0, None), (3, 0.0, None), (4, 0.0, 0.0),
                                                  (3, 27.5, 27.5), (4, 30.0, 30.0)])
def test_zero_temperature_outside_production_is_unknown(mode, temp, expected):
    assert d.inverter_state(producing_block(Mode=mode, Temp=temp))["temperature"] == expected


class Day:
    def __init__(self):
        self.value = date(2026, 11, 23)

    def __call__(self):
        return self.value


async def test_energy_today_is_held_when_inverter_resets_it_in_the_evening(tmp_path):
    client, day = FakeClient(), Day()
    pub = Publisher("0.1.0", False, energy_today_file=tmp_path / "e.json", today=day)
    await pub.attach(client)

    pub.handle_telemetry(producing_block(EdayAC=1600.0))
    pub.handle_telemetry(producing_block(Mode=3, EdayAC=0.0))
    await pub.flush()

    assert client.last(d.INVERTER_STATE_TOPIC)["energy_today"] == 1600


async def test_energy_today_resets_on_the_next_day(tmp_path):
    client, day = FakeClient(), Day()
    pub = Publisher("0.1.0", False, energy_today_file=tmp_path / "e.json", today=day)
    await pub.attach(client)
    pub.handle_telemetry(producing_block(EdayAC=1600.0))

    day.value = date(2026, 11, 24)
    pub.handle_telemetry(producing_block(Mode=2, EdayAC=0.0))
    await pub.flush()

    assert client.last(d.INVERTER_STATE_TOPIC)["energy_today"] == 0


async def test_held_energy_today_survives_restart(tmp_path):
    day, file = Day(), tmp_path / "e.json"
    Publisher("0.1.0", False, energy_today_file=file, today=day).handle_telemetry(producing_block(EdayAC=1600.0))
    client = FakeClient()
    pub = Publisher("0.1.0", False, energy_today_file=file, today=day)
    await pub.attach(client)

    pub.handle_telemetry(producing_block(Mode=3, EdayAC=0.0))
    await pub.flush()

    assert client.last(d.INVERTER_STATE_TOPIC)["energy_today"] == 1600


async def test_decreasing_lifetime_energy_is_ignored():
    client, pub = FakeClient(), Publisher("0.1.0", optimizer_details=False)
    await pub.attach(client)

    pub.handle_telemetry(producing_block(Etotal_i=129_340_000))
    pub.handle_telemetry(producing_block(Etotal_i=1000))
    await pub.flush()

    assert client.last(d.INVERTER_STATE_TOPIC)["energy_total"] == 129_340.0


async def test_unchanged_state_is_not_republished():
    client, pub = FakeClient(), Publisher("0.1.0", optimizer_details=False)
    await pub.attach(client)
    block = next(parse0500(optimizer_block(0x1012ABCD, 30, 20, 1, 5, 20)))

    pub.handle_telemetry(block)
    await pub.flush()
    pub.handle_telemetry(block)
    await pub.flush()

    assert client.topics().count(d.optimizer_state_topic("1012ABCD")) == 1


async def test_optimizer_gets_own_device_with_details_disabled_by_default():
    client, pub = FakeClient(), Publisher("0.1.0", optimizer_details=True)
    await pub.attach(client)

    pub.handle_telemetry(next(parse0500(optimizer_block(0x1012ABCD, 20, 19, 1.5, 5, 20))))
    await pub.flush()

    config = client.last(d.discovery_topic("solaredge_local_optimizer_1012abcd"))
    assert config["device"]["via_device"] == d.INVERTER_DEVICE_ID
    assert "enabled_by_default" not in config["components"]["power"]
    assert config["components"]["v_in"]["enabled_by_default"] is False
    assert client.last(d.optimizer_state_topic("1012ABCD"))["power"] == 30.0


async def test_device_info_updates_inverter_discovery_and_is_persisted(tmp_path):
    info_file = tmp_path / "device_info.json"
    client, pub = FakeClient(), Publisher("0.1.0", False, info_file)
    await pub.attach(client)

    pub.handle_telemetry(next(parse0500(device_info_block(0x7F012345, ["SolarEdge", "SE10K", "7F012345"]))))
    await pub.flush()

    device = client.last(d.discovery_topic(d.INVERTER_DEVICE_ID))["device"]
    assert (device["model"], device["serial_number"]) == ("SE10K", "7F012345")
    assert Publisher("0.1.0", False, info_file)._model == "SE10K"


async def test_capture_state_drives_availability_topic():
    client, pub = FakeClient(), Publisher("0.1.0", optimizer_details=False)
    await pub.attach(client)

    pub.set_capture_state("connected")
    await pub.flush()
    pub.set_capture_state("disconnected")
    await pub.flush()

    assert [p for t, p in client.messages if t == d.CAPTURE_TOPIC] == ["online", "offline"]


async def test_state_is_kept_while_broker_is_disconnected():
    client, pub = FakeClient(), Publisher("0.1.0", optimizer_details=False)

    pub.handle_telemetry(producing_block())
    await pub.flush()
    await pub.attach(client)

    assert d.INVERTER_STATE_TOPIC in client.topics()
