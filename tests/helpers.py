import os
import struct

from app.crypto import SEDecrypt
from app.solaredge import FN_ENCRYPTED, build_message

INVERTER = 0x7F054321
SERVER = 0xFFFFFFFD


def encrypt(key: bytes, msg0503: bytes, plain: bytes) -> bytes:
    """Inverse of SEDecrypt.decrypt: XOR with a 4-byte mask, then the same CTR keystream."""
    counter = os.urandom(16)
    filler = os.urandom(2)
    mask = os.urandom(4)
    masked = bytes(b ^ mask[i & 3] for i, b in enumerate(plain))
    return bytes(SEDecrypt(key, msg0503).apply_keystream(counter + filler + mask + masked))


def encrypted_message(key: bytes, msg0503: bytes, inner: bytes, seq: int = 1) -> bytes:
    return build_message(seq, INVERTER, SERVER, FN_ENCRYPTED, encrypt(key, msg0503, inner))


def optimizer_block(dev_id: int, v_in: float, v_out: float, i_in: float, e_day: int,
                    temp: int, uptime: int = 1234, ts: int = 1_700_000_000) -> bytes:
    vin, vout, iin = round(v_in * 8), round(v_out * 8), round(i_in * 160)
    t = (temp // 2) & 0xFF
    body = bytes([
        uptime & 0xFF, uptime >> 8,
        vin & 0xFF, ((vin >> 8) & 0x03) | ((vout & 0x3F) << 2),
        ((vout >> 6) & 0x0F) | ((iin & 0x0F) << 4), (iin >> 4) & 0xFF,
        e_day & 0xFF, e_day >> 8,
        t,
    ])
    return struct.pack("<HLHL", 0x0080, dev_id, 13, ts) + body


def inverter3_block(dev_id: int, ts: int = 1_700_000_000, **values) -> bytes:
    from app.solaredge import SEDataInverter3
    fields = SEDataInverter3._fields
    ints = {"uptime", "interval", "Mode", "Etotal_i", "L1"}
    defaults = {f: (0 if f in ints else 0.0) for f in fields}
    defaults.update(values)
    body = struct.pack("<LLffffffffffffffffffffffffLffffffffffffffffffffLL", *(defaults[f] for f in fields))
    return struct.pack("<HLHL", 0x0011, dev_id, 200, ts) + body


def device_info_block(dev_id: int, strings: list[str], ts: int = 1_700_000_000) -> bytes:
    body = b"\0".join(s.encode() for s in strings) + b"\0"
    return struct.pack("<HLHL", 0x0017, dev_id, len(body) + 4, ts) + body


def ethernet_tcp_frame(src_ip: bytes, dst_ip: bytes, sport: int, dport: int, seq: int,
                       flags: int, data: bytes, pad_to: int = 60) -> bytes:
    tcp = struct.pack(">HHIIBBHHH", sport, dport, seq, 0, 5 << 4, flags, 65535, 0, 0) + data
    total = 20 + len(tcp)
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, total, 0, 0, 64, 6, 0, src_ip, dst_ip) + tcp
    frame = b"\x00" * 12 + b"\x08\x00" + ip
    return frame + b"\x00" * max(0, pad_to - len(frame))


def pcap_stream(frames: list[bytes], modified: bool = True) -> bytes:
    magic = b"\xa1\xb2\xcd\x34" if modified else b"\xa1\xb2\xc3\xd4"
    out = magic + struct.pack(">HHiIII", 2, 4, 0, 0, 1600, 1)
    for f in frames:
        rec = struct.pack(">IIII", 0, 0, len(f), len(f))
        if modified:
            rec += b"\x00" * 8
        out += rec + f
    return out
