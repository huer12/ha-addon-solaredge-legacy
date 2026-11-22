#!/usr/bin/env python3
"""
tr064_reconnect_test.py - test whether blocking the inverter's internet access via the
FRITZ!Box (TR-064 X_AVM-DE_HostFilter) forces a reconnect with a new session key (0x0503).

What it does:
  1. starts the FRITZ!Box capture of the inverter's traffic (same as se_fritz_live.py)
  2. waits until the capture is running
  3. blocks the inverter's internet access (DisallowWANAccessByIP = 1)
  4. waits --block-seconds (default 180 s, longer than the inverter's 2-min keep-alive)
  5. unblocks it again (always, also on Ctrl+C or errors)
  6. reports when the old connection died, when a new TCP connection started,
     and whether a new 0x0503 session key arrived and decrypts

Requirements: se_fritz_live.py in the same folder, pycryptodome (or cryptography).
FRITZ!Box: TR-064 must be enabled ("Heimnetz > Netzwerk > Netzwerkeinstellungen >
Zugriff für Anwendungen zulassen"), user needs the "FRITZ!Box Einstellungen" permission.

PowerShell:
  $env:FRITZ_PASSWORD = 'your-fritzbox-password'
  py tr064_reconnect_test.py --user solar-capture --inverter-ip 192.168.178.50 --key <32-hex-key>

Only check / undo the block (no capture):
  py tr064_reconnect_test.py --user solar-capture --inverter-ip 192.168.178.50 --status
  py tr064_reconnect_test.py --user solar-capture --inverter-ip 192.168.178.50 --unblock
"""
import argparse
import getpass
import os
import re
import struct
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

import se_fritz_live as sfl

HOSTFILTER = "urn:dslforum-org:service:X_AVM-DE_HostFilter:1"

# --------------------------------------------------------------------------- TR-064


class Tr064:
    def __init__(self, host, user, password, port=49000):
        host = re.sub(r"^https?://", "", host).split("/")[0].split(":")[0]
        self.base = "http://%s:%d" % (host, port)
        mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
        mgr.add_password(None, self.base, user, password)
        self.opener = urllib.request.build_opener(urllib.request.HTTPDigestAuthHandler(mgr))
        self.control_url = None

    def discover(self):
        xml = urllib.request.urlopen(self.base + "/tr64desc.xml", timeout=10).read()
        root = ET.fromstring(xml)
        for svc in root.iter():
            if svc.tag.endswith("service"):
                st = next((c.text for c in svc if c.tag.endswith("serviceType")), "")
                if st == HOSTFILTER:
                    self.control_url = next(c.text for c in svc if c.tag.endswith("controlURL"))
                    return self.control_url
        raise RuntimeError("FRITZ!Box offers no %s service (TR-064 disabled or too old FRITZ!OS?)" % HOSTFILTER)

    def call(self, action, **args):
        if not self.control_url:
            self.discover()
        body = ('<?xml version="1.0" encoding="utf-8"?>'
                '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
                's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>'
                '<u:%s xmlns:u="%s">%s</u:%s></s:Body></s:Envelope>') % (
            action, HOSTFILTER, "".join("<%s>%s</%s>" % (k, v, k) for k, v in args.items()), action)
        req = urllib.request.Request(self.base + self.control_url, data=body.encode(), headers={
            "Content-Type": 'text/xml; charset="utf-8"',
            "SOAPAction": '"%s#%s"' % (HOSTFILTER, action)})
        try:
            resp = self.opener.open(req, timeout=15).read().decode()
        except urllib.error.HTTPError as e:
            detail = e.read().decode(errors="replace")
            code = re.search(r"<errorCode>(\d+)</errorCode>", detail)
            desc = re.search(r"<errorDescription>(.*?)</errorDescription>", detail)
            raise RuntimeError("TR-064 %s failed: HTTP %d %s %s" % (
                action, e.code, code.group(1) if code else "", desc.group(1) if desc else "")) from None
        return dict(re.findall(r"<(New\w+)>(.*?)</New\w+>", resp))

    def get_access(self, ip):
        return self.call("GetWANAccessByIP", NewIPv4Address=ip)

    def set_blocked(self, ip, blocked):
        self.call("DisallowWANAccessByIP", NewIPv4Address=ip, NewDisallow=1 if blocked else 0)

# --------------------------------------------------------------------------- observing the capture


class Observer:
    """Collects the events we care about, with timestamps."""

    def __init__(self):
        self.events = []
        self.capture_running = threading.Event()
        self.new_key = threading.Event()
        self.decrypted_after_key = threading.Event()
        self.t0 = time.time()

    def event(self, text):
        self.events.append((time.time(), text))
        sfl.log(text)


class ObservingDecoder(sfl.SolarEdgeDecoder):
    def __init__(self, key, obs):
        super().__init__(key, state_file=None, on_telemetry=self._telemetry)
        self.obs = obs

    def _telemetry(self, t):
        if t["kind"].startswith("inverter"):
            self.obs.event("Telemetry decrypted: inverter P=%s W" % round(sum(
                (t.get(k) or 0) for k in ("Pactive1", "Pactive2", "Pactive3", "Pactive"))))
            if self.obs.new_key.is_set():
                self.obs.decrypted_after_key.set()

    def handle(self, hdr, payload, inner=False):
        fn = hdr[3]
        if fn == sfl.FN_SESSION_KEY:
            self.obs.event("NEW SESSION KEY 0x0503 received")
            self.obs.new_key.set()
        elif fn == sfl.FN_ENCRYPTED and self.decryptor is None:
            return  # no key yet, stay quiet
        elif inner and fn == 0x0080 and self.obs.new_key.is_set():
            self.obs.decrypted_after_key.set()
        super().handle(hdr, payload, inner)


def watch_tcp_flags(frame, obs, inverter_ip):
    """Log SYN/FIN/RST of the inverter's connections and DNS queries."""
    if len(frame) < 34 or frame[12:14] != b"\x08\x00":
        return
    ip = frame[14:]
    ihl = (ip[0] & 0x0F) * 4
    src = ".".join(map(str, ip[12:16]))
    dst = ".".join(map(str, ip[16:20]))
    if ip[9] == 17:  # UDP
        sport, dport = struct.unpack(">HH", ip[ihl:ihl + 4])
        if dport == 53 and src == inverter_ip:
            obs.event("DNS query from inverter")
        return
    if ip[9] != 6:
        return
    tcp = ip[ihl:]
    sport, dport = struct.unpack(">HH", tcp[:4])
    flags = tcp[13]
    names = [n for bit, n in ((0x02, "SYN"), (0x01, "FIN"), (0x04, "RST")) if flags & bit]
    if names and not (flags & 0x10 and names == ["SYN"]):  # skip SYN-ACK noise
        obs.event("TCP %s %s:%d -> %s:%d" % ("/".join(names), src, sport, dst, dport))


def capture_thread(fb, args, key, obs, stop):
    dec = ObservingDecoder(key, obs)
    bpf = "host %s" % args.inverter_ip
    while not stop.is_set():
        try:
            resp = fb.capture(args.iface, bpf)
            obs.event("Capture running (HTTP %s)" % resp.status)
            obs.capture_running.set()
            tcp = sfl.TcpReassembler(dec)
            for frame in sfl.pcap_frames(resp):
                watch_tcp_flags(frame, obs, args.inverter_ip)
                tcp.packet(frame)
                if stop.is_set():
                    break
        except Exception as e:
            if not stop.is_set():
                obs.event("Capture error: %s: %s" % (type(e).__name__, e))
                time.sleep(5)
                try:
                    fb.login()
                except Exception:
                    pass

# --------------------------------------------------------------------------- main


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="fritz.box")
    ap.add_argument("--user", required=True)
    ap.add_argument("--password-file")
    ap.add_argument("--inverter-ip", required=True)
    ap.add_argument("--key", help="inverter key, 32 hex characters")
    ap.add_argument("--iface", default="1-lan")
    ap.add_argument("--block-seconds", type=int, default=180)
    ap.add_argument("--wait-minutes", type=int, default=15, help="how long to wait for a new key after unblocking")
    ap.add_argument("--status", action="store_true", help="only show the current block status")
    ap.add_argument("--unblock", action="store_true", help="only remove the block")
    a = ap.parse_args()

    if os.environ.get("FRITZ_PASSWORD"):
        password = os.environ["FRITZ_PASSWORD"]
    elif a.password_file:
        with open(a.password_file, encoding="utf-8-sig") as f:
            password = f.readline().rstrip("\r\n")
    else:
        password = getpass.getpass("FRITZ!Box password: ")

    tr = Tr064(a.host, a.user, password)
    tr.discover()
    sfl.log("TR-064 HostFilter found at %s%s" % (tr.base, tr.control_url))
    sfl.log("Current status for %s: %s" % (a.inverter_ip, tr.get_access(a.inverter_ip)))
    if a.status:
        return
    if a.unblock:
        tr.set_blocked(a.inverter_ip, False)
        sfl.log("Unblocked. Status now: %s" % tr.get_access(a.inverter_ip))
        return
    if not a.key:
        ap.error("--key is required for the test")

    key = bytes.fromhex(a.key)
    fb = sfl.FritzBox(a.host, a.user, password)
    fb.login()
    obs = Observer()
    stop = threading.Event()
    th = threading.Thread(target=capture_thread, args=(fb, a, key, obs, stop), daemon=True)
    th.start()
    if not obs.capture_running.wait(30):
        sys.exit("Capture did not start - check with se_fritz_live.py first")
    time.sleep(5)

    blocked = False
    try:
        obs.event(">>> BLOCKING internet access of %s for %d s" % (a.inverter_ip, a.block_seconds))
        tr.set_blocked(a.inverter_ip, True)
        blocked = True
        sfl.log("Status: %s" % tr.get_access(a.inverter_ip))
        end = time.time() + a.block_seconds
        while time.time() < end:
            time.sleep(min(10, end - time.time()))
    finally:
        # always try to unblock, even if blocking seemed to fail
        if True:
            for attempt in range(5):
                try:
                    tr.set_blocked(a.inverter_ip, False)
                    obs.event("<<< UNBLOCKED internet access of %s (status %s)" % (
                        a.inverter_ip, tr.get_access(a.inverter_ip)))
                    break
                except Exception as e:
                    sfl.log("Unblock attempt %d failed: %s" % (attempt + 1, e))
                    time.sleep(3)
            else:
                sfl.log("!!! COULD NOT UNBLOCK. Run again with --unblock, or remove the block in the "
                        "FRITZ!Box UI (Internet > Filter > Kindersicherung / device access).")

    try:
        sfl.log("Waiting up to %d min for a new session key ..." % a.wait_minutes)
        got = obs.new_key.wait(a.wait_minutes * 60)
        if got:
            obs.decrypted_after_key.wait(300)
    except KeyboardInterrupt:
        pass
    stop.set()
    fb.stop(a.iface)

    print("\n===== Timeline =====")
    for t, text in obs.events:
        print("%+7.0f s  %s" % (t - obs.t0, text))
    print("\nResult:", "SUCCESS - new session key received%s" % (
        " and messages decrypt" if obs.decrypted_after_key.is_set() else "")
        if obs.new_key.is_set() else "NO new session key within %d min" % a.wait_minutes)


if __name__ == "__main__":
    main()
