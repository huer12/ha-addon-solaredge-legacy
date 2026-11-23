from datetime import date

from app import discovery as d
from app.mqtt import OPTIMIZER_CHECK_DELAY_S, Publisher
from app.optimizer_check import evaluate
from app.solaredge import parse0500
from helpers import inverter3_block, optimizer_block
from test_mqtt import FakeClient


def test_relative_yield_against_median():
    result = evaluate({"A": 100, "B": 100, "C": 80, "D": 102}, {"A", "B", "C", "D"})

    assert result.relative_yield == {"A": 100.0, "B": 100.0, "C": 80.0, "D": 102.0}
    assert result.underperforming == {"C": 80.0}
    assert result.missing == []


def test_known_optimizer_without_report_today_is_missing():
    result = evaluate({"A": 100, "B": 100}, {"A", "B", "C"})

    assert result.missing == ["C"]
    assert result.relative_yield["C"] is None
    assert "C" not in result.underperforming


def test_dark_day_is_not_evaluated():
    assert evaluate({"A": 5, "B": 6}, {"A", "B"}) is None
    assert evaluate({}, {"A"}) is None


class Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


def inverter(mode):
    return next(parse0500(inverter3_block(0x7F012345, Mode=mode)))


def optimizer(opt_id, e_day):
    return next(parse0500(optimizer_block(opt_id, 30, 20, 1, e_day, 20)))


async def test_check_runs_once_after_production_stops_and_publishes_results(tmp_path):
    # Arrange
    clock, client = Clock(), FakeClient()
    pub = Publisher("0.3.0", False, tmp_path, today=lambda: date(2026, 11, 23), clock=clock)
    await pub.attach(client)
    pub.handle_telemetry(inverter(4))
    for opt_id, wh in ((0x10000001, 500), (0x10000002, 510), (0x10000003, 300)):
        pub.handle_telemetry(optimizer(opt_id, wh))

    # Act
    pub.handle_telemetry(inverter(3))
    await pub.flush()
    early = d.OPTIMIZER_CHECK_TOPIC in client.topics()
    clock.now += OPTIMIZER_CHECK_DELAY_S
    await pub.flush()

    # Assert
    assert not early
    check = client.last(d.OPTIMIZER_CHECK_TOPIC)
    assert check["underperforming_optimizers"] == 1
    assert check["underperforming"] == {"10000003": 60.0}
    assert client.last(d.optimizer_daily_topic("10000001"))["relative_yield"] == 100.0
    clock.now += OPTIMIZER_CHECK_DELAY_S
    client.messages.clear()
    await pub.flush()
    assert d.OPTIMIZER_CHECK_TOPIC not in client.topics()


async def test_known_optimizers_survive_restart_and_count_as_missing(tmp_path):
    clock, today = Clock(), (lambda: date(2026, 11, 23))
    first = Publisher("0.3.0", False, tmp_path, today=today, clock=clock)
    first.handle_telemetry(optimizer(0x10000009, 400))
    client = FakeClient()
    pub = Publisher("0.3.0", False, tmp_path, today=today, clock=clock)
    await pub.attach(client)

    pub.handle_telemetry(inverter(4))
    pub.handle_telemetry(optimizer(0x10000001, 500))
    pub.handle_telemetry(optimizer(0x10000002, 500))
    pub.handle_telemetry(inverter(2))
    clock.now += OPTIMIZER_CHECK_DELAY_S
    await pub.flush()

    assert client.last(d.OPTIMIZER_CHECK_TOPIC)["missing"] == ["10000009"]
    assert d.discovery_topic(d.optimizer_device_id("10000009")) in client.topics()


def test_discovery_contains_check_entities():
    inv = d.inverter_discovery("0.3.0", None, None)["components"]
    opt = d.optimizer_discovery("0.3.0", "10000001", False)["components"]

    assert inv["underperforming_optimizers"]["json_attributes_topic"] == d.OPTIMIZER_CHECK_TOPIC
    assert opt["relative_yield"]["state_topic"] == d.optimizer_daily_topic("10000001")
    assert opt["relative_yield"]["unit_of_measurement"] == "%"
