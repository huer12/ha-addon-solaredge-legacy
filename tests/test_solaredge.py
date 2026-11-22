import os

import pytest

from app.solaredge import (FN_KEEPALIVE, FN_SESSION_KEY, FN_TELEMETRY, NO_VALUE, Decoder,
                           build_message, parse0500, split_messages)
from helpers import (INVERTER, SERVER, device_info_block, encrypted_message, inverter3_block,
                     optimizer_block)


def test_split_messages_returns_valid_message_and_consumes_buffer():
    buf = bytearray(build_message(7, INVERTER, SERVER, FN_KEEPALIVE, b"abc"))

    messages = list(split_messages(buf))

    assert messages == [((7, INVERTER, SERVER, FN_KEEPALIVE), b"abc")]
    assert buf == b""


def test_split_messages_resyncs_after_garbage_and_skips_bad_crc():
    good = build_message(2, INVERTER, SERVER, FN_KEEPALIVE, b"ok")
    bad = bytearray(build_message(1, INVERTER, SERVER, FN_KEEPALIVE, b"xx"))
    bad[-1] ^= 0xFF
    buf = bytearray(b"\x01\x02garbage" + bad + good)

    messages = list(split_messages(buf))

    assert [p for _, p in messages] == [b"ok"]


def test_split_messages_waits_for_incomplete_message():
    msg = build_message(1, INVERTER, SERVER, FN_KEEPALIVE, b"0123456789")
    buf = bytearray(msg[:-3])

    assert list(split_messages(buf)) == []

    buf += msg[-3:]
    assert len(list(split_messages(buf))) == 1


def test_parse_optimizer_block():
    block = optimizer_block(0x1012ABCD, v_in=30.5, v_out=19.375, i_in=1.25, e_day=812, temp=-6)

    (opt,) = parse0500(block)

    assert opt["kind"] == "optimizer"
    assert opt["id"] == "1012ABCD"
    assert opt["v_in"] == 30.5
    assert opt["v_out"] == 19.375
    assert opt["i_in"] == 1.25
    assert opt["e_day_wh"] == 812
    assert opt["temperature"] == -6


def test_parse_inverter3_masks_device_id_and_maps_no_value_to_none():
    block = inverter3_block(0x7F812345, Vac1=238.5, Idc=NO_VALUE, Mode=5, Etotal_i=129_340_000)

    (inv,) = parse0500(block)

    assert inv["kind"] == "inverter_3ph"
    assert inv["id"] == "7F012345"
    assert inv["Vac1"] == pytest.approx(238.5)
    assert inv["Idc"] is None
    assert inv["Mode"] == 5
    assert inv["Etotal_i"] == 129_340_000


def test_parse_multiple_blocks_including_device_info():
    data = (device_info_block(0x7F012345, ["SolarEdge", "SE10K", "7F012345"])
            + optimizer_block(0x1, 30, 20, 1, 5, 20)
            + optimizer_block(0x2, 30, 20, 1, 5, 20))

    kinds = [b["kind"] for b in parse0500(data)]

    assert kinds == ["device_info", "optimizer", "optimizer"]
    assert next(parse0500(data))["strings"] == ["SolarEdge", "SE10K", "7F012345"]


class Recorder:
    def __init__(self):
        self.telemetry, self.session_keys, self.key_states = [], [], []


def make_decoder(key, saved=None):
    r = Recorder()
    dec = Decoder(key, r.telemetry.append, r.session_keys.append, r.key_states.append, saved)
    return dec, r


def feed(dec, raw: bytes):
    for hdr, payload in split_messages(bytearray(raw)):
        dec.handle(hdr, payload)


def test_decoder_decrypts_telemetry_after_session_key():
    key, msg0503 = os.urandom(16), os.urandom(34)
    dec, rec = make_decoder(key)
    telemetry = build_message(3, INVERTER, SERVER, FN_TELEMETRY, optimizer_block(0xAB, 30, 20, 1, 5, 20))

    feed(dec, build_message(1, INVERTER, SERVER, FN_SESSION_KEY, msg0503))
    feed(dec, encrypted_message(key, msg0503, telemetry))

    assert rec.session_keys == [msg0503]
    assert rec.key_states == [True]
    assert [t["id"] for t in rec.telemetry] == ["000000AB"]


def test_decoder_ignores_encrypted_message_without_session_key():
    key, msg0503 = os.urandom(16), os.urandom(34)
    dec, rec = make_decoder(key)

    feed(dec, encrypted_message(key, msg0503, build_message(1, INVERTER, SERVER, FN_KEEPALIVE, b"")))

    assert rec.telemetry == [] and rec.key_states == []


def test_decoder_discards_outdated_saved_session_key():
    key, current, outdated = os.urandom(16), os.urandom(34), os.urandom(34)
    dec, rec = make_decoder(key, saved=outdated)
    inner = build_message(1, INVERTER, SERVER, FN_KEEPALIVE, b"")

    feed(dec, encrypted_message(key, current, inner))
    feed(dec, encrypted_message(key, current, inner))

    assert rec.key_states == []
    assert dec.session_key_valid is False


def test_decoder_accepts_matching_saved_session_key():
    key, msg0503 = os.urandom(16), os.urandom(34)
    dec, rec = make_decoder(key, saved=msg0503)

    feed(dec, encrypted_message(key, msg0503, build_message(1, INVERTER, SERVER, FN_KEEPALIVE, b"")))

    assert rec.key_states == [True]
