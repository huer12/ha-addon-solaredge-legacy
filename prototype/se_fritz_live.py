#!/usr/bin/env python3
"""
se_fritz_live.py - read SolarEdge inverter telemetry live from a FRITZ!Box packet capture.

Logs in to the FRITZ!Box, starts an endless packet capture filtered to the inverter,
reassembles the TCP stream, decrypts the SolarEdge messages with the inverter key
and prints inverter + optimizer values.

Decryption and telemetry parsing are taken from se-logger by Jerrythafast (GPLv3),
https://github.com/Jerrythafast/se-logger - this file is therefore GPLv3 as well.
FRITZ!Box login/capture approach as in https://github.com/arn-c0de/fritzdump

Requirements:  py -m pip install pycryptodome   (or the 'cryptography' package)

Live (Windows):
  py se_fritz_live.py --user myuser --inverter-ip 192.168.178.50 --key <32-hex-key> --save today.eth
Offline test on an existing capture:
  py se_fritz_live.py --replay today.eth --key <32-hex-key>
List capture interfaces of the FRITZ!Box:
  py se_fritz_live.py --user myuser --list-ifaces
"""
import argparse
import getpass
import hashlib
import json
import os
import re
import struct
import sys
import time
import urllib.parse
import urllib.request
from collections import namedtuple

try:  # pycryptodome
    from Crypto.Cipher import AES
except ImportError:
    try:  # pycryptodomex
        from Cryptodome.Cipher import AES
    except ImportError:
        try:  # cryptography
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

            class AES:
                MODE_ECB = None

                @staticmethod
                def new(key, mode=None):
                    return Cipher(algorithms.AES(bytes(key)), modes.ECB()).encryptor()
        except ImportError:
            sys.exit("Missing AES library. Install it with:  py -m pip install pycryptodome")

BARKER = b"\x12\x34\x56\x79"
FN_ENCRYPTED = 0x003D
FN_SESSION_KEY = 0x0503
FN_TELEMETRY = 0x0500

# --------------------------------------------------------------------------- se-logger (GPLv3)

def calc_crc(data):
    crc = 0x5A5A
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
    return crc


class SEDecrypt:
    def __init__(self, key, msg0503):
        c = AES.new(key, mode=AES.MODE_ECB)
        enkey1 = c.update(bytes(msg0503[0:16])) if hasattr(c, 'update') else c.encrypt(bytes(msg0503[0:16]))
        self.cipher = AES.new(bytes(enkey1[i] ^ msg0503[i + 16] for i in range(16)),
                              mode=AES.MODE_ECB)

    def decrypt(self, msg003d):
        msg003d = bytearray(msg003d)
        rand1 = bytearray(msg003d[0:16])
        rand = self.cipher.update(bytes(rand1)) if hasattr(self.cipher, 'update') else self.cipher.encrypt(bytes(rand1))
        posa, posb = 0, 16
        while posb < len(msg003d):
            msg003d[posb] ^= rand[posa]
            posb += 1
            posa += 1
            if posa == 16:
                posa = 0
                for posc in range(15, -1, -1):
                    rand1[posc] = (rand1[posc] + 1) & 0xFF
                    if rand1[posc]:
                        break
                rand = self.cipher.update(bytes(rand1)) if hasattr(self.cipher, 'update') else self.cipher.encrypt(bytes(rand1))
        return bytes(msg003d[i + 22] ^ msg003d[18 + (i & 3)] for i in range(len(msg003d) - 22))


REROUND = lambda x: None if x == -3.4028234663852886e+38 else x
SEDataInverter1 = namedtuple("SEDataInverter1",
    "uptime interval Temp EdayAC DeltaEdayAC Vac Iac Freq EdayDC DeltaEdayDC Vdc Idc Etotal_f Ircd "
    "f1 CosPhi Mode GndFltR PowerLimit IoutDC f3 f4 Pactive Papparent Preactive f5 f6 f7 Etotal_i L1")
SEDataInverter3 = namedtuple("SEDataInverter3",
    "uptime interval Temp EdayAC DeltaEdayAC Vac1 Vac2 Vac3 Iac1 Iac2 Iac3 Freq1 Freq2 Freq3 EdayDC "
    "DeltaEdayDC Vdc Idc Etotal_f Ircd f1_1 f1_2 f1_3 CosPhi1 CosPhi2 CosPhi3 Mode GndFltR PowerLimit "
    "IoutDC1 IoutDC2 IoutDC3 V1to2 V2to3 V3to1 Pactive1 Pactive2 Pactive3 Papparent1 Papparent2 "
    "Papparent3 Preactive1 Preactive2 Preactive3 f5 f6 f7 Etotal_i L1")


def parse0500(data):
    pos = 0
    while pos + 12 <= len(data):
        typ, dev_id, length, ts = struct.unpack("<HLHL", data[pos:pos + 12])
        if typ == 0x0080 and length == 13:  # optimizer
            b = data[pos + 12: pos + 8 + length]
            yield {
                "kind": "optimizer", "id": "%08X" % dev_id, "timestamp": ts,
                "uptime_s": b[0] | (b[1] << 8),
                "v_in": (b[2] | ((b[3] & 0x03) << 8)) / 8,
                "v_out": ((b[3] >> 2) | ((b[4] & 0x0F) << 6)) / 8,
                "i_in": ((b[4] >> 4) | (b[5] << 4)) / 160,
                "e_day_wh": b[6] | (b[7] << 8),
                "temperature": ((b[8] | ~0xFF) if b[8] & 0x80 else b[8]) * 2,
            }
        elif typ == 0x0010 and length in (124, 174, 180, 186):  # 1-phase inverter
            inv = SEDataInverter1._make(map(REROUND, struct.unpack(
                "<LLffffffffffffffLfffffffffffLL", data[pos + 12:pos + 12 + 120])))
            yield {"kind": "inverter_1ph", "id": "%08X" % (dev_id & ~0x00800000), "timestamp": ts,
                   **inv._asdict()}
        elif typ == 0x0011 and length in (200, 264, 266):  # 3-phase inverter
            inv = SEDataInverter3._make(map(REROUND, struct.unpack(
                "<LLffffffffffffffffffffffffLffffffffffffffffffffLL", data[pos + 12:pos + 12 + 196])))
            yield {"kind": "inverter_3ph", "id": "%08X" % (dev_id & ~0x00800000), "timestamp": ts,
                   **inv._asdict()}
        else:
            yield {"kind": "unknown", "type": "0x%04x" % typ, "id": "%08X" % dev_id, "length": length}
        pos += length + 8

# --------------------------------------------------------------------------- SolarEdge framing


def split_messages(buf):
    """Take complete SolarEdge messages from the front of bytearray buf (modified in place)."""
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


class SolarEdgeDecoder:
    def __init__(self, key, state_file=None, on_telemetry=None):
        self.key = key
        self.state_file = state_file
        self.on_telemetry = on_telemetry or print_telemetry
        self.decryptor = None
        if state_file:
            try:
                with open(state_file, "rb") as f:
                    self.decryptor = SEDecrypt(key, f.read())
                log("Loaded saved session key from %s" % state_file)
            except OSError:
                pass

    def handle(self, hdr, payload, inner=False):
        fn = hdr[3]
        if fn == FN_ENCRYPTED:
            if not self.decryptor:
                log("Encrypted message (%d bytes) - no session key yet, waiting for 0x0503" % len(payload))
                return
            inner_buf = bytearray(self.decryptor.decrypt(payload))
            got = False
            for h, p in split_messages(inner_buf):
                got = True
                self.handle(h, p, inner=True)
            if not got:
                log("Decryption produced no valid message - wrong key or outdated session key")
        elif fn == FN_SESSION_KEY:
            log("Session key message 0x0503 received%s" % (" (encrypted)" if inner else ""))
            self.decryptor = SEDecrypt(self.key, payload)
            if self.state_file:
                with open(self.state_file, "wb") as f:
                    f.write(payload)
        elif fn == FN_TELEMETRY:
            for t in parse0500(payload):
                self.on_telemetry(t)
        else:
            log("Message 0x%04x (%d bytes)%s" % (fn, len(payload), " [decrypted]" if inner else ""))

# --------------------------------------------------------------------------- TCP reassembly


class TcpReassembler:
    """Very small per-direction TCP reassembler feeding SolarEdge framing."""

    def __init__(self, decoder):
        self.decoder = decoder
        self.flows = {}

    def packet(self, frame):
        if len(frame) < 34 or frame[12:14] != b"\x08\x00":
            return
        ip = frame[14:]
        ihl = (ip[0] & 0x0F) * 4
        total = struct.unpack(">H", ip[2:4])[0]
        if ip[9] != 6:
            return
        ip = ip[:total]
        tcp = ip[ihl:]
        sport, dport, seq = struct.unpack(">HHI", tcp[:8])
        flags = tcp[13]
        data = tcp[(tcp[12] >> 4) * 4:]
        key = (bytes(ip[12:16]), sport, bytes(ip[16:20]), dport)
        flow = self.flows.get(key)
        if flags & 0x02 or flow is None:  # SYN or first time seen
            flow = self.flows[key] = {"next": (seq + 1) & 0xFFFFFFFF if flags & 0x02 else seq,
                                      "pending": {}, "buf": bytearray()}
            if flags & 0x02:
                return
        if not data:
            return
        flow["pending"].setdefault(seq, data)
        self._drain(flow)

    def _drain(self, flow):
        progressed = True
        while progressed:
            progressed = False
            for seq in sorted(flow["pending"]):
                data = flow["pending"][seq]
                diff = (seq - flow["next"]) & 0xFFFFFFFF
                if diff == 0:
                    flow["buf"] += data
                elif diff > 0x7FFFFFFF:  # retransmission / overlap
                    overlap = (flow["next"] - seq) & 0xFFFFFFFF
                    if overlap < len(data):
                        flow["buf"] += data[overlap:]
                    else:
                        del flow["pending"][seq]
                        progressed = True
                        break
                else:
                    continue
                flow["next"] = (seq + len(data)) & 0xFFFFFFFF
                del flow["pending"][seq]
                progressed = True
                break
        if len(flow["pending"]) > 50:  # give up a lost gap
            first = min(flow["pending"])
            log("TCP gap, skipping ahead")
            flow["next"] = first
            self._drain(flow)
        for hdr, payload in split_messages(flow["buf"]):
            self.decoder.handle(hdr, payload)

# --------------------------------------------------------------------------- pcap stream


def read_exact(stream, n):
    out = b""
    while len(out) < n:
        chunk = stream.read(n - len(out))
        if not chunk:
            raise EOFError
        out += chunk
    return out


def pcap_frames(stream):
    try:
        head = read_exact(stream, 24)
    except EOFError:
        raise RuntimeError("FRITZ!Box closed the stream without sending any data "
                           "(wrong --iface id, missing permission, or capture already running)")
    magic = head[:4]
    if magic in (b"\xa1\xb2\xcd\x34", b"\x34\xcd\xb2\xa1"):  # modified pcap (FRITZ!Box)
        rec_len = 24
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1"):
        rec_len = 16
    else:
        raise ValueError("Unknown capture format %s" % magic.hex())
    endian = ">" if magic[0] == 0xA1 else "<"
    while True:
        try:
            rec = read_exact(stream, rec_len)
        except EOFError:
            return
        _, _, incl, _ = struct.unpack(endian + "IIII", rec[:16])
        yield read_exact(stream, incl)


class TeeReader:
    def __init__(self, stream, save):
        self.stream, self.save = stream, save

    def read(self, n):
        data = self.stream.read(n)
        if self.save and data:
            self.save.write(data)
            self.save.flush()
        return data

# --------------------------------------------------------------------------- FRITZ!Box


class FritzBox:
    def __init__(self, host, user, password):
        self.base = host if host.startswith("http") else "http://" + host
        self.user, self.password = user, password
        self.sid = None

    def login(self):
        xml = urllib.request.urlopen(self.base + "/login_sid.lua?version=2", timeout=10).read().decode()
        challenge = re.search(r"<Challenge>(.*?)</Challenge>", xml).group(1)
        block = int(re.search(r"<BlockTime>(\d+)</BlockTime>", xml).group(1))
        if block:
            log("FRITZ!Box login blocked for %ds, waiting" % block)
            time.sleep(block)
        if challenge.startswith("2$"):
            _, it1, salt1, it2, salt2 = challenge.split("$")
            h1 = hashlib.pbkdf2_hmac("sha256", self.password.encode(), bytes.fromhex(salt1), int(it1))
            h2 = hashlib.pbkdf2_hmac("sha256", h1, bytes.fromhex(salt2), int(it2))
            response = salt2 + "$" + h2.hex()
        else:
            md5 = hashlib.md5((challenge + "-" + self.password).encode("utf-16le")).hexdigest()
            response = challenge + "-" + md5
        q = urllib.parse.urlencode({"username": self.user, "response": response})
        xml = urllib.request.urlopen(self.base + "/login_sid.lua?version=2&" + q, timeout=10).read().decode()
        sid = re.search(r"<SID>(.*?)</SID>", xml).group(1)
        if set(sid) == {"0"}:
            raise RuntimeError("FRITZ!Box login failed (user/password?)")
        self.sid = sid

    def list_ifaces(self):
        body = urllib.parse.urlencode({"sid": self.sid, "page": "cap", "lang": "en"}).encode()
        raw = urllib.request.urlopen(self.base + "/data.lua", body, timeout=10).read().decode()
        rows = re.findall(r"<th>(.*?)</th>\s*<td[^>]*>\s*<button[^>]*name=\"start\"[^>]*value=\"([^\"]+)\"", raw, re.S)
        if rows:
            for name, value in rows:
                print("  %-12s %s" % (value, name))
        else:
            print(raw[:6000])

    def capture(self, iface, bpf, snaplen=1600):
        # quote_via=quote: spaces must be %20, the FRITZ!Box does not decode '+' as space
        q = urllib.parse.urlencode({"ifaceorminor": iface, "snaplen": snaplen, "filter": bpf,
                                    "capture": "Start", "sid": self.sid}, quote_via=urllib.parse.quote)
        # timeout: if nothing arrives for 10 minutes, reconnect
        return urllib.request.urlopen(self.base + "/cgi-bin/capture_notimeout?" + q, timeout=600)

    def stop(self, iface):
        q = urllib.parse.urlencode({"ifaceorminor": iface, "capture": "Stop", "sid": self.sid})
        try:
            urllib.request.urlopen(self.base + "/cgi-bin/capture_notimeout?" + q, timeout=5).read()
        except Exception:
            pass

# --------------------------------------------------------------------------- output


def log(msg):
    print(time.strftime("%H:%M:%S"), msg, flush=True)


def fmt(v):
    return "%.2f" % v if isinstance(v, float) else str(v)


def print_telemetry(t):
    if t["kind"].startswith("inverter"):
        keep = ["Temp", "Vdc", "Idc", "EdayAC", "Etotal_i", "Mode", "Pactive", "Vac", "Iac", "Freq",
                "Pactive1", "Pactive2", "Pactive3", "Vac1", "Vac2", "Vac3", "Iac1", "Iac2", "Iac3", "Freq1"]
        log("INVERTER %s  " % t["id"] + "  ".join("%s=%s" % (k, fmt(t[k])) for k in keep if k in t))
    elif t["kind"] == "optimizer":
        log("OPTIMIZER %s  Vin=%.1fV Vout=%.1fV Iin=%.2fA Eday=%dWh T=%d°C" % (
            t["id"], t["v_in"], t["v_out"], t["i_in"], t["e_day_wh"], t["temperature"]))
    else:
        log("Telemetry block %s" % t)

# --------------------------------------------------------------------------- main


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="fritz.box")
    ap.add_argument("--user", help="FRITZ!Box user (needs 'FRITZ!Box settings' permission)")
    ap.add_argument("--password-file", help="read the FRITZ!Box password from this file (first line)")
    ap.add_argument("--inverter-ip", help="IP of the inverter, used as capture filter")
    ap.add_argument("--key", required=False, help="inverter key, 32 hex characters")
    ap.add_argument("--iface", default="1-lan", help="capture interface id (default 1-lan)")
    ap.add_argument("--save", help="also save the raw capture (a timestamp is added to the name)")
    ap.add_argument("--state", default="se_session_key.bin", help="file to keep the last 0x0503 session key")
    ap.add_argument("--replay", help="decode an existing capture file instead of streaming")
    ap.add_argument("--list-ifaces", action="store_true")
    a = ap.parse_args()

    if a.replay:
        key = bytes.fromhex(a.key)
        dec = SolarEdgeDecoder(key, a.state)
        tcp = TcpReassembler(dec)
        with open(a.replay, "rb") as f:
            for frame in pcap_frames(f):
                tcp.packet(frame)
        return

    if not a.user:
        ap.error("--user is required for live mode")
    if os.environ.get("FRITZ_PASSWORD"):
        password = os.environ["FRITZ_PASSWORD"]
    elif a.password_file:
        with open(a.password_file, encoding="utf-8-sig") as f:
            password = f.readline().rstrip("\r\n")
    else:
        password = getpass.getpass("FRITZ!Box password (input stays hidden; right-click or Ctrl+V to paste): ")
    fb = FritzBox(a.host, a.user, password)
    fb.login()
    log("Logged in to FRITZ!Box")
    if a.list_ifaces:
        fb.list_ifaces()
        return
    if not (a.key and a.inverter_ip):
        ap.error("--key and --inverter-ip are required for live mode")
    key = bytes.fromhex(a.key)
    dec = SolarEdgeDecoder(key, a.state)
    save = None
    bpf = "host %s" % a.inverter_ip
    backoff = 5
    try:
        while True:
            try:
                log("Starting capture on %s with filter '%s'" % (a.iface, bpf))
                resp = fb.capture(a.iface, bpf)
                log("FRITZ!Box answered HTTP %s, content-type %s" % (resp.status, resp.headers.get("Content-Type")))
                if a.save:
                    if save:
                        save.close()
                    base, dot, ext = a.save.rpartition(".")
                    name = "%s-%s.%s" % (base or a.save, time.strftime("%Y%m%d-%H%M%S"), ext if dot else "eth")
                    save = open(name, "wb")
                    log("Saving raw capture to %s" % name)
                tcp = TcpReassembler(dec)
                for frame in pcap_frames(TeeReader(resp, save)):
                    tcp.packet(frame)
                    backoff = 5
                log("Capture stream ended")
            except KeyboardInterrupt:
                raise
            except Exception as e:  # network error, FRITZ!Box reboot, expired session ...
                log("Capture error: %s: %s" % (type(e).__name__, e))
            time.sleep(backoff)
            backoff = min(backoff * 2, 300)
            try:
                fb.login()
            except Exception as e:
                log("Re-login failed: %s" % e)
    except KeyboardInterrupt:
        log("Stopping")
        fb.stop(a.iface)
    finally:
        if save:
            save.close()


if __name__ == "__main__":
    main()
