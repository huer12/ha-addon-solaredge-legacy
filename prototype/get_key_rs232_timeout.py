#!/usr/bin/env python3
"""
Read the SolarEdge encryption key over RS232, with a timeout so it never hangs.
Based on get-key-by-rs232.py from se-logger (GPLv3, Jerrythafast).

Usage (Windows):  py get_key_rs232_timeout.py COM4 7F012345
Usage (Linux):    python3 get_key_rs232_timeout.py /dev/ttyUSB0 7F012345
"""
import struct
import sys

import serial  # py -m pip install pyserial

if len(sys.argv) < 3:
    sys.exit(__doc__)
PORT = sys.argv[1]
INVERTER_ID = int(sys.argv[2], 16)
BAUD = 115200
TIMEOUT = 3  # seconds per request


def crc16(data):
    crc = 0x5A5A
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
    return crc


def get_key_part(conn, seq):
    param = 0x238 + seq
    crc = crc16(struct.pack(">HLLH", seq, 0xFFFFFFFD, INVERTER_ID, 0x12)
                + struct.pack("<H", param))
    msg = struct.pack("<LHHHLLHHH", 0x79563412, 2, 0xFFFD, seq,
                      0xFFFFFFFD, INVERTER_ID, 0x12, param, crc)
    conn.reset_input_buffer()
    conn.write(msg)
    conn.flush()
    print(f"  sent     {msg.hex(' ')}")
    resp = conn.read(28)
    print(f"  received {resp.hex(' ') if resp else '(nothing)'}")
    if len(resp) < 28:
        return None
    return resp[-8:-4]


def main():
    print(f"Port {PORT}, inverter ID 0x{INVERTER_ID:08X}, {BAUD} baud")
    try:
        conn = serial.Serial(PORT, BAUD, timeout=TIMEOUT, write_timeout=TIMEOUT)
    except serial.SerialException as e:
        sys.exit(f"Cannot open {PORT}: {e}")

    key = b""
    with conn:
        for seq in range(1, 5):
            print(f"Requesting key part {seq}/4 (param 0x{0x238 + seq:04X})")
            part = get_key_part(conn, seq)
            if part is None:
                sys.exit(
                    "\nNo (complete) answer from the inverter. Check:\n"
                    "  - inverter ID (ID screen on the display, first 8 characters)\n"
                    "  - adapter is real RS232 (+/-12 V), not 3.3 V TTL\n"
                    "  - TX/RX not swapped, GND connected\n"
                    "  - no other program has the COM port open")
            key += part

    print("\nYour key (se-logger format): '" + "".join(f"\\x{b:02x}" for b in key) + "'")
    print("Your key (hex):               " + key.hex())


if __name__ == "__main__":
    main()
