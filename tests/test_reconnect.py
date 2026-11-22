import os

import pytest

from app import reconnect
from app.reconnect import MIN_INTERVAL_S, WAIT_FOR_KEY_S, ForcedReconnect, ReconnectTrigger
from app.solaredge import FN_KEEPALIVE, FN_SESSION_KEY, Decoder, build_message, split_messages
from app.tr064 import HOSTFILTER, Tr064Error, find_control_url, soap_envelope
from helpers import INVERTER, SERVER, encrypted_message


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def test_trigger_is_due_only_after_wait_time_without_valid_key():
    clock = Clock()
    trigger = ReconnectTrigger(clock)

    trigger.undecryptable_traffic()
    clock.now += WAIT_FOR_KEY_S - 1
    assert not trigger.due()

    clock.now += 1
    assert trigger.due()


def test_valid_key_resets_trigger():
    clock = Clock()
    trigger = ReconnectTrigger(clock)
    trigger.undecryptable_traffic()

    trigger.key_valid()
    clock.now += WAIT_FOR_KEY_S * 2

    assert not trigger.due()


def test_trigger_is_rate_limited():
    clock = Clock()
    trigger = ReconnectTrigger(clock)
    trigger.undecryptable_traffic()
    clock.now += WAIT_FOR_KEY_S
    trigger.attempted()

    clock.now += MIN_INTERVAL_S - 1
    assert not trigger.due()

    clock.now += 1
    assert trigger.due()


def test_decoder_reports_undecryptable_traffic_until_session_key_arrives():
    key, msg0503 = os.urandom(16), os.urandom(34)
    trigger = ReconnectTrigger()
    calls = []
    dec = Decoder(key, lambda t: None, on_key_state=lambda v: trigger.key_valid() if v else None,
                  on_undecryptable=lambda: calls.append(1))
    inner = build_message(1, INVERTER, SERVER, FN_KEEPALIVE, b"")

    for raw in (encrypted_message(key, msg0503, inner),
                build_message(2, INVERTER, SERVER, FN_SESSION_KEY, msg0503),
                encrypted_message(key, msg0503, inner)):
        for hdr, payload in split_messages(bytearray(raw)):
            dec.handle(hdr, payload)

    assert calls == [1]
    assert dec.session_key_valid


class FakeHostFilter:
    def __init__(self, fail_block=False, unblock_failures=0):
        self.calls = []
        self.fail_block = fail_block
        self.unblock_failures = unblock_failures

    async def set_blocked(self, ip, blocked):
        self.calls.append((ip, blocked))
        if blocked and self.fail_block:
            raise Tr064Error("boom")
        if not blocked and self.unblock_failures:
            self.unblock_failures -= 1
            raise Tr064Error("busy")


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    async def instant(_):
        pass
    monkeypatch.setattr(reconnect.asyncio, "sleep", instant)


async def test_force_blocks_then_unblocks_and_clears_flag(tmp_path):
    fb = FakeHostFilter()
    flag = tmp_path / "blocked"

    await ForcedReconnect(fb, "192.168.178.50", ReconnectTrigger(), flag).force()

    assert fb.calls == [("192.168.178.50", True), ("192.168.178.50", False)]
    assert not flag.exists()


async def test_force_unblocks_even_if_block_fails_and_retries_unblock(tmp_path):
    fb = FakeHostFilter(fail_block=True, unblock_failures=2)

    await ForcedReconnect(fb, "10.0.0.5", ReconnectTrigger(), tmp_path / "blocked").force()

    assert [b for _, b in fb.calls] == [True, False, False, False]


async def test_leftover_block_from_crash_is_removed(tmp_path):
    fb, flag = FakeHostFilter(), tmp_path / "blocked"
    flag.touch()

    await ForcedReconnect(fb, "10.0.0.5", ReconnectTrigger(), flag).recover_from_crash()

    assert fb.calls == [("10.0.0.5", False)]
    assert not flag.exists()


async def test_no_unblock_on_start_without_flag(tmp_path):
    fb = FakeHostFilter()

    await ForcedReconnect(fb, "10.0.0.5", ReconnectTrigger(), tmp_path / "blocked").recover_from_crash()

    assert fb.calls == []


def test_find_control_url_in_tr64_description():
    xml = (b'<root xmlns="urn:dslforum-org:device-1-0"><device><serviceList>'
           b'<service><serviceType>urn:dslforum-org:service:Other:1</serviceType>'
           b'<controlURL>/upnp/control/other</controlURL></service>'
           b'<service><serviceType>' + HOSTFILTER.encode() + b'</serviceType>'
           b'<controlURL>/upnp/control/x_hostfilter</controlURL></service>'
           b'</serviceList></device></root>')

    assert find_control_url(xml, HOSTFILTER) == "/upnp/control/x_hostfilter"


def test_soap_envelope_contains_action_and_arguments():
    body = soap_envelope("DisallowWANAccessByIP", HOSTFILTER, {"NewIPv4Address": "10.0.0.5", "NewDisallow": 1})

    assert '<u:DisallowWANAccessByIP xmlns:u="%s">' % HOSTFILTER in body
    assert "<NewIPv4Address>10.0.0.5</NewIPv4Address><NewDisallow>1</NewDisallow>" in body
