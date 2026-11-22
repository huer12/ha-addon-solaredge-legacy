# Prototype scripts

Working reference scripts from the initial investigation. The add-on is built from these.

## se_fritz_live.py – live decoder

Logs in to the FRITZ!Box, streams a packet capture of the inverter's traffic, decrypts the
SolarEdge messages and prints inverter and optimizer values.

PowerShell example (password in an environment variable, so it is not stored in a file or the command history line):

```powershell
$env:FRITZ_PASSWORD = 'your-fritzbox-password'
py se_fritz_live.py --user solar-capture --inverter-ip 192.168.178.50 --key <32-hex-key> --save test.eth
```

Use single quotes around the password so PowerShell does not interpret characters like `$`.
The variable only lives in the current PowerShell window.

Requirements:

```powershell
py -m pip install pycryptodome   # or: py -m pip install cryptography
```

Other options:

| Option | Purpose |
|---|---|
| `--list-ifaces` | list the FRITZ!Box capture interfaces (lan = `1-lan`) |
| `--iface 1-lan` | capture interface (default `1-lan`) |
| `--password-file <file>` | read the password from the first line of a file instead |
| `--save test.eth` | also save the raw capture (a timestamp is added to the name) |
| `--state se_session_key.bin` | where the last session key (0x0503) is stored |
| `--replay <file>.eth --key <key>` | decode a saved capture offline |

Notes:
- Decryption needs the session key (0x0503), which the inverter only sends when it (re)connects.
  If you start the script mid-session, unplug the inverter's LAN cable for ~30 s to force a reconnect.
- Ctrl+C on Windows only reacts when the next packet arrives (up to ~2 min); closing the window always works.

## tr064_reconnect_test.py – force a new session key (experiment)

Tests whether briefly blocking the inverter's internet access via the FRITZ!Box (TR-064
`X_AVM-DE_HostFilter` → `DisallowWANAccessByIP`) makes the inverter reconnect and send a new
session key (0x0503). It runs the capture, blocks for `--block-seconds` (default 180 s, longer than the
2-min keep-alive), always unblocks again, then waits for the new key and prints a timeline.

```powershell
$env:FRITZ_PASSWORD = 'your-fritzbox-password'
py tr064_reconnect_test.py --user solar-capture --inverter-ip 192.168.178.50 --key <32-hex-key>
```

- Needs `se_fritz_live.py` in the same folder.
- FRITZ!Box: enable TR-064 under *Heimnetz > Netzwerk > Netzwerkeinstellungen > Zugriff für Anwendungen zulassen*;
  the user needs the *FRITZ!Box Einstellungen* permission.
- `--status` shows the current block state, `--unblock` removes a block (if something went wrong).
- Options: `--block-seconds`, `--wait-minutes` (default 15).

## get_key_rs232_timeout.py – read the inverter key

Reads the inverter's private encryption key over the RS232 port (USB-RS232 adapter with real RS232 levels).
Based on se-logger's `get-key-by-rs232.py`, with a 3 s timeout and hex output.

```powershell
py -m pip install pyserial
py get_key_rs232_timeout.py COM4 7F012345
```

Arguments: serial port, inverter ID (first 8 characters of the ID screen on the inverter display).

**Never commit the key, the password, captures or the session-key file.**

## Credits
- FRITZ!Box capture: [fritzdump](https://github.com/arn-c0de/fritzdump)
- Decryption, parsing, key reading: [se-logger](https://github.com/Jerrythafast/se-logger) (GPLv3)
