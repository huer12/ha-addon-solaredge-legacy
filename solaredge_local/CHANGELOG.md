# Changelog

## 0.2.1
- Energy today keeps the day's value when the inverter resets its counter in the evening.
- Temperature is unknown instead of 0 °C while the inverter is not producing.
- Status texts for modes 3 (Wake-up), 4 (Producing), 5 (Producing, throttled) and the other SunSpec states.

## 0.2.0
- New option `force_reconnect` (default on): gets a new session key via TR-064 when the inverter
  traffic can't be decrypted for 10 minutes.

## 0.1.0
- First version: FRITZ!Box capture, decryption, inverter and optimizer entities via MQTT discovery.
