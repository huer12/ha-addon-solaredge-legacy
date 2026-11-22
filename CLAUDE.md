# SolarEdge Local – Home Assistant add-on

Home Assistant add-on repository with one add-on (`solaredge_local/`) that reads telemetry from
older SolarEdge inverters **locally** (no SolarEdge cloud API) and publishes it via **MQTT discovery**.
Developed and verified against an SE10K 3-phase inverter, CPU firmware 2.1054, behind a FRITZ!Box 7590.

## Why this approach
- CPU firmware 2.x has no SunSpec/Modbus (needs CPU ≥ 3.x, the hardware can't be upgraded) and no
  server-address setting, so the inverter can't be pointed at HA.
- The inverter sends encrypted telemetry to SolarEdge over TCP. With the inverter's private key
  (read once over RS232) the traffic can be decrypted.
- The FRITZ!Box streams a live packet capture over HTTP. The add-on captures only the inverter's
  traffic, decrypts and publishes it. Nothing changes on the inverter; the cloud keeps working.
- **Add-on + MQTT** instead of a custom integration: the add-on keeps running while HA Core restarts,
  so the session key is not lost.

## Layout
```
repository.yaml               HA add-on repository descriptor
solaredge_local/              the add-on: config.yaml, Dockerfile, build.yaml, run.sh, DOCS.md, translations/
  app/
    config.py                 options from /data/options.json, MQTT settings from the Supervisor
    fritzbox.py               FRITZ!Box login + capture stream (aiohttp)
    pcap.py, tcp.py           incremental pcap parser, minimal TCP reassembly
    crypto.py, solaredge.py   CRC, decryption, framing, 0x0500 telemetry parsing, Decoder
    discovery.py, mqtt.py     MQTT device discovery and state publishing
    tr064.py, reconnect.py    forced reconnect via TR-064 HostFilter
    main.py                   wiring, backoff loops, --replay mode
tests/                        pytest, synthetic messages built in tests/helpers.py
prototype/                    original reference scripts (live decoder, RS232 key reader, TR-064 test)
```
Run tests: `.\.venv\Scripts\python -m pytest` (see README for setup).

## Protocol

### FRITZ!Box capture stream
1. `GET /login_sid.lua?version=2` → `<Challenge>`, `<BlockTime>`.
   PBKDF2 challenge `2$<iter1>$<salt1>$<iter2>$<salt2>`:
   `h1 = pbkdf2_sha256(pw, salt1, iter1)`, `h2 = pbkdf2_sha256(h1, salt2, iter2)`,
   response = `salt2 + "$" + h2.hex()`. Then `GET /login_sid.lua?version=2&username=…&response=…` → `<SID>`
   (all zeros = failed). The user needs the "FRITZ!Box Einstellungen" permission.
2. `GET /cgi-bin/capture_notimeout?ifaceorminor=1-lan&snaplen=1600&filter=host%20<inverter-ip>&capture=Start&sid=…`
   → endless `application/octet-stream`.
   - **Spaces in `filter` MUST be `%20`.** With `+` the box closes the stream at once with zero bytes.
3. Stop: `…/capture_notimeout?ifaceorminor=1-lan&capture=Stop&sid=…`
4. Interface list: `POST /data.lua` with `sid`, `page=cap` → HTML with `<button name="start" value="1-lan">`.
- Stream format: **modified pcap** ("Kuznetzov"), magic `a1 b2 cd 34` (big endian),
  24-byte global header, **24-byte record headers**.
- Ethernet frames are padded to 60 bytes → **trim the IP payload with the IP total-length field**.

### SolarEdge framing
`12 34 56 79 | len (u16 LE) | ~len (u16 LE) | seq (u16) | src (u32) | dst (u32) | func (u16) | payload[len] | crc16 (u16)`
- CRC16 (poly 0xA001 reflected, init 0x5A5A) over `struct.pack(">HLLH", seq, src, dst, func) + payload`.
- Resync on the barker; validate len/~len and CRC.
- Server: `prod2.solaredge.com`, TCP 22222, one long-lived connection.

### Encryption
- Outer messages are **0x003d**. The session key arrives in a **0x0503** message (34 bytes).
- `SEDecrypt(key, msg0503)` → AES-ECB keystream; the decrypted 0x003d payload is again one or more
  framed messages (a valid CRC proves decryption worked). The cipher is an XOR keystream, so tests
  encrypt with the same transform.
- **Session key** is exchanged when the TCP connection is (re)established, roughly daily. A saved key
  stops working after that. Starting mid-session = no data until the next reconnect.
- Blocking the inverter's internet access for 180 s via TR-064 (`X_AVM-DE_HostFilter:1` →
  `DisallowWANAccessByIP`) forces a reconnect and a new 0x0503 (verified, see
  `prototype/tr064_reconnect_test.py`). Implemented as option `force_reconnect`: triggers after 10 min of
  undecryptable traffic, max once per hour, always unblocks (flag file in `/data` covers crashes).
- Decrypted function codes seen: `0x0080` (keep-alive, empty, every ~2 min), `0x0501`, `0x0580` (8 B),
  `0x0500` (telemetry, every ~2–4 min).

### 0x0500 telemetry blocks (`<HLHL`: type, device id, length, timestamp, then body)
- `0x0011` 3-phase inverter, length 200 → `SEDataInverter3` layout (196 bytes). Device id: mask out `0x00800000`.
- `0x0080` optimizer, length 13. Scaling (verified against Vdc and AC power):
  `v_in = (b2 | (b3&3)<<8)/8`, `v_out = ((b3>>2) | (b4&0xF)<<6)/8`, `i_in = ((b4>>4) | b5<<4)/160`,
  `e_day = b6 | b7<<8` (Wh), `temp = signed(b8)*2`, `uptime = b0 | b1<<8`.
- `0x0017` device info: NUL-separated "SolarEdge", model, serial + sub-device list → MQTT device info.
- `0x0018` country, `0x0300`, `0x0800`: unknown, logged at debug.
- `-3.4028234663852886e+38` = "no value" → None. `Idc` is always "no value" on this firmware.
- **Vac/Freq are garbage right after boot / at night** (seen 2.7e6 V, −5279 Hz) → only published when
  plausible (Vac 150–300 V, Freq 45–55 Hz).
- Mode: 2 = night/sleep, 5 = producing (others unknown; published raw too).
- `Etotal_i` (u32, Wh) → energy-dashboard sensor (kWh, total_increasing); a decreasing value is ignored.

## Design decisions
- One capture session; reconnect with backoff 5 s → 300 s; read timeout 10 min (keep-alive every 2 min).
- Publish only on change (retained); log only state changes.
- Availability: `solaredge_local/status` (LWT) + `solaredge_local/capture`; telemetry entities need both.
- Inverter device has a fixed identifier `solaredge_local_inverter`, so status entities exist before the
  first telemetry; model/serial are added from 0x0017.
- **Each optimizer is its own device** (`via_device` = inverter). Power and energy today enabled;
  Vin, Vout, Iin, temperature only with `optimizer_details` and disabled by default (recorder load:
  ~40 optimizers × 6 values would be >100k rows/day).
- Required options have no default in `config.yaml`, so the Supervisor refuses to start until they are set.

## Licensing
Decryption and parsing code comes from **se-logger** (https://github.com/Jerrythafast/se-logger, GPLv3),
so the project is **GPLv3**. Credit se-logger, jbuehl/solaredge and arn-c0de/fritzdump.

## Secrets and personal data – never commit
The inverter key, FRITZ!Box password, captures (`*.eth`, `*.pcap`), `se_session_key.bin`,
`options.local.json`, password files (see `.gitignore`). The repo is public: also keep real inverter
serials, optimizer IDs, IPs, MAC addresses and user names out of code, tests and docs; use made-up
examples. For local replay tests read the key from env var `SE_KEY` and captures from `captures/`.

## References
- **fritzdump** – https://github.com/arn-c0de/fritzdump – FRITZ!Box login, capture streaming, stop call.
- **se-logger** – https://github.com/Jerrythafast/se-logger – decryption, 0x0500 parsing, RS232 key reading. GPLv3.
- **jbuehl/solaredge** – https://github.com/jbuehl/solaredge – original protocol reverse engineering
  (encryption support removed in Sept 2025, commit 6505f60).
