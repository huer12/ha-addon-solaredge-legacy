# SolarEdge Local

Reads inverter and optimizer data from older SolarEdge inverters (CPU firmware 2.x, no SunSpec/Modbus)
**locally** and publishes it to Home Assistant via MQTT discovery.

The FRITZ!Box streams a packet capture of the inverter's own traffic to the SolarEdge cloud. The app
decrypts it with the inverter's key. Nothing changes on the inverter and the SolarEdge cloud keeps working.

## Requirements
- Mosquitto broker app installed and running, MQTT integration set up in Home Assistant.
- The inverter is connected by LAN to a FRITZ!Box and has a fixed IP address.
- A dedicated FRITZ!Box user with the **FRITZ!Box settings** permission.
- The inverter's encryption key (32 hex characters), read once over RS232.

## Configuration
All values are entered on the **Configuration** tab. The app does not start until the required ones are set.

| Option | Description | Example |
|---|---|---|
| `fritzbox_host` | FRITZ!Box host name or IP (default `fritz.box`) | `fritz.box` or `192.168.178.1` |
| `fritzbox_user` | FRITZ!Box user | `solar-capture` |
| `fritzbox_password` | FRITZ!Box password | `MySecretPassword` |
| `inverter_ip` | IPv4 address of the inverter | `192.168.178.31` |
| `inverter_key` | Inverter key, 32 hex characters | `0123456789abcdef0123456789abcdef` |
| `capture_interface` | FRITZ!Box capture interface (default `1-lan`) | `1-lan` |
| `optimizer_details` | Also create voltage/current/temperature entities per optimizer (disabled by default) | `false` |
| `force_reconnect` | Get a new session key automatically via TR-064, see below (default on) | `true` |
| `log_level` | `debug`, `info`, `warning`, `error` | `info` |

Passwords and the key are hidden in the UI but stored unencrypted in the app's data on the Home Assistant
host and included in backups. Use encrypted backups.

## Session key
The inverter only sends its session key when it (re)connects to the SolarEdge server, usually once a day.
The key is saved and reused after app restarts.

With `force_reconnect` on, the app gets a new key by itself: if the inverter's traffic can't be decrypted
for 10 minutes, it blocks the inverter's internet access for 3 minutes via TR-064
(`X_AVM-DE_HostFilter`), then unblocks it. The inverter notices the dead connection, reconnects and sends
a new key. This happens at most once per hour. The inverter is always unblocked again, also after an
app crash (on the next start). For this, enable **Heimnetz → Netzwerk → Netzwerkeinstellungen →
Zugriff für Anwendungen zulassen** in the FRITZ!Box.

TR-064 is a standard SOAP/UPnP interface for configuring routers from the local network. AVM uses it
for FRITZ!Box apps and adds its own services, such as `X_AVM-DE_HostFilter`, the per-device internet
block from the FRITZ!Box UI under Internet → Filter. It only works from the local network and uses the
same FRITZ!Box user as the capture. Documentation:
[FRITZ!Box interfaces (AVM)](https://fritz.com/pages/schnittstellen), section "Apps / TR-064".

Without `force_reconnect`, unplug the inverter's LAN cable for about 30 seconds to force a new key.

## Entities
- **SolarEdge Inverter**: AC power (total and per phase), AC voltage/current per phase, frequency,
  DC voltage, temperature, energy today, energy total (for the energy dashboard), status, plus
  diagnostics (capture state, session key, last telemetry).
- **Optimizer &lt;id&gt;**: one device per optimizer, linked to the inverter: power and energy today.
  Optimizers appear one by one as they report.

Telemetry entities become unavailable when the FRITZ!Box capture is down.

## Credits
- [se-logger](https://github.com/Jerrythafast/se-logger) – decryption and telemetry parsing (GPLv3)
- [jbuehl/solaredge](https://github.com/jbuehl/solaredge) – protocol reverse engineering
- [fritzdump](https://github.com/arn-c0de/fritzdump) – FRITZ!Box capture approach
