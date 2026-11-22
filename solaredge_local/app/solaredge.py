# Framing and telemetry parsing taken from se-logger by Jerrythafast (GPLv3),
# https://github.com/Jerrythafast/se-logger
import logging
import struct
from collections import namedtuple
from collections.abc import Callable, Iterator

from .crypto import SEDecrypt, calc_crc

log = logging.getLogger(__name__)

BARKER = b"\x12\x34\x56\x79"
FN_KEEPALIVE = 0x0080
FN_ENCRYPTED = 0x003D
FN_SESSION_KEY = 0x0503
FN_TELEMETRY = 0x0500

NO_VALUE = -3.4028234663852886e38

SEDataInverter1 = namedtuple("SEDataInverter1",
    "uptime interval Temp EdayAC DeltaEdayAC Vac Iac Freq EdayDC DeltaEdayDC Vdc Idc Etotal_f Ircd "
    "f1 CosPhi Mode GndFltR PowerLimit IoutDC f3 f4 Pactive Papparent Preactive f5 f6 f7 Etotal_i L1")
SEDataInverter3 = namedtuple("SEDataInverter3",
    "uptime interval Temp EdayAC DeltaEdayAC Vac1 Vac2 Vac3 Iac1 Iac2 Iac3 Freq1 Freq2 Freq3 EdayDC "
    "DeltaEdayDC Vdc Idc Etotal_f Ircd f1_1 f1_2 f1_3 CosPhi1 CosPhi2 CosPhi3 Mode GndFltR PowerLimit "
    "IoutDC1 IoutDC2 IoutDC3 V1to2 V2to3 V3to1 Pactive1 Pactive2 Pactive3 Papparent1 Papparent2 "
    "Papparent3 Preactive1 Preactive2 Preactive3 f5 f6 f7 Etotal_i L1")

Header = tuple[int, int, int, int]


def _none_if_no_value(x):
    return None if x == NO_VALUE else x


def build_message(seq: int, src: int, dst: int, fn: int, payload: bytes) -> bytes:
    crc = calc_crc(struct.pack(">HLLH", seq, src, dst, fn) + payload)
    length = len(payload)
    return (BARKER + struct.pack("<HHHLLH", length, ~length & 0xFFFF, seq, src, dst, fn)
            + payload + struct.pack("<H", crc))


def split_messages(buf: bytearray) -> Iterator[tuple[Header, bytes]]:
    """Take complete, CRC-valid messages from the front of buf (modified in place)."""
    while True:
        i = buf.find(BARKER)
        if i < 0:
            del buf[:max(0, len(buf) - 3)]
            return
        del buf[:i]
        if len(buf) < 20:
            return
        length, inv_length = struct.unpack("<HH", buf[4:8])
        if length != (~inv_length & 0xFFFF):
            del buf[:1]
            continue
        if len(buf) < 22 + length:
            return
        seq, src, dst, fn = struct.unpack("<HLLH", buf[8:20])
        payload = bytes(buf[20:20 + length])
        crc = struct.unpack("<H", buf[20 + length:22 + length])[0]
        if crc != calc_crc(struct.pack(">HLLH", seq, src, dst, fn) + payload):
            del buf[:1]
            continue
        del buf[:22 + length]
        yield (seq, src, dst, fn), payload


def _parse_optimizer(dev_id: int, ts: int, b: bytes) -> dict:
    return {
        "kind": "optimizer", "id": "%08X" % dev_id, "timestamp": ts,
        "uptime_s": b[0] | (b[1] << 8),
        "v_in": (b[2] | ((b[3] & 0x03) << 8)) / 8,
        "v_out": ((b[3] >> 2) | ((b[4] & 0x0F) << 6)) / 8,
        "i_in": ((b[4] >> 4) | (b[5] << 4)) / 160,
        "e_day_wh": b[6] | (b[7] << 8),
        "temperature": (b[8] - 256 if b[8] & 0x80 else b[8]) * 2,
    }


def _parse_device_info(dev_id: int, ts: int, body: bytes) -> dict:
    strings = [s.decode("latin-1") for s in body.split(b"\0") if s]
    return {"kind": "device_info", "id": "%08X" % dev_id, "timestamp": ts, "strings": strings}


def parse0500(data: bytes) -> Iterator[dict]:
    pos = 0
    while pos + 12 <= len(data):
        typ, dev_id, length, ts = struct.unpack("<HLHL", data[pos:pos + 12])
        body = data[pos + 12:pos + 8 + length]
        inverter_id = "%08X" % (dev_id & ~0x00800000)
        if typ == 0x0080 and length == 13:
            yield _parse_optimizer(dev_id, ts, body)
        elif typ == 0x0010 and length in (124, 174, 180, 186):
            inv = SEDataInverter1._make(map(_none_if_no_value, struct.unpack(
                "<LLffffffffffffffLfffffffffffLL", body[:120])))
            yield {"kind": "inverter_1ph", "id": inverter_id, "timestamp": ts, **inv._asdict()}
        elif typ == 0x0011 and length in (200, 264, 266):
            inv = SEDataInverter3._make(map(_none_if_no_value, struct.unpack(
                "<LLffffffffffffffffffffffffLffffffffffffffffffffLL", body[:196])))
            yield {"kind": "inverter_3ph", "id": inverter_id, "timestamp": ts, **inv._asdict()}
        elif typ == 0x0017:
            yield _parse_device_info(dev_id, ts, body)
        else:
            yield {"kind": "unknown", "type": "0x%04x" % typ, "id": "%08X" % dev_id,
                   "length": length, "body": body.hex()}
        pos += length + 8


class Decoder:
    def __init__(self, key: bytes,
                 on_telemetry: Callable[[dict], None],
                 on_session_key: Callable[[bytes], None] = lambda _: None,
                 on_key_state: Callable[[bool], None] = lambda _: None,
                 saved_session_key: bytes | None = None,
                 on_undecryptable: Callable[[], None] = lambda: None):
        self._key = key
        self._on_telemetry = on_telemetry
        self._on_session_key = on_session_key
        self._on_key_state = on_key_state
        self._on_undecryptable = on_undecryptable
        self._decryptor = None
        self.session_key_valid = False
        if saved_session_key:
            try:
                self._decryptor = SEDecrypt(key, saved_session_key)
                log.info("Loaded saved session key, it is checked with the next encrypted message")
            except ValueError as e:
                log.warning("Ignoring saved session key: %s", e)

    def handle(self, hdr: Header, payload: bytes, inner: bool = False) -> None:
        fn = hdr[3]
        if fn == FN_ENCRYPTED:
            self._handle_encrypted(payload)
        elif fn == FN_SESSION_KEY:
            log.info("Session key received%s", " (inside encrypted message)" if inner else "")
            self._decryptor = SEDecrypt(self._key, payload)
            self._on_session_key(payload)
        elif fn == FN_TELEMETRY:
            for t in parse0500(payload):
                if t["kind"] == "unknown":
                    log.debug("Unknown telemetry block %s", t)
                else:
                    self._on_telemetry(t)
        else:
            log.debug("Message 0x%04x (%d bytes)%s", fn, len(payload), " [decrypted]" if inner else "")

    def _handle_encrypted(self, payload: bytes) -> None:
        if not self._decryptor:
            log.debug("Encrypted message (%d bytes) without session key, waiting for 0x0503", len(payload))
            self._on_undecryptable()
            return
        inner_buf = bytearray(self._decryptor.decrypt(payload))
        messages = list(split_messages(inner_buf))
        if not messages:
            log.warning("Session key does not decrypt the inverter traffic, waiting for a new one "
                        "(the inverter sends it when it reconnects)")
            self._decryptor = None
            self._set_key_state(False)
            self._on_undecryptable()
            return
        self._set_key_state(True)
        for h, p in messages:
            self.handle(h, p, inner=True)

    def _set_key_state(self, valid: bool) -> None:
        if valid != self.session_key_valid:
            self.session_key_valid = valid
            self._on_key_state(valid)
