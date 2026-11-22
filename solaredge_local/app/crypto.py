# Taken from se-logger by Jerrythafast (GPLv3), https://github.com/Jerrythafast/se-logger
from Crypto.Cipher import AES


def calc_crc(data: bytes) -> int:
    crc = 0x5A5A
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
    return crc


class SEDecrypt:
    def __init__(self, key: bytes, msg0503: bytes):
        if len(msg0503) < 32:
            raise ValueError("session key message too short: %d bytes" % len(msg0503))
        enkey1 = AES.new(key, AES.MODE_ECB).encrypt(bytes(msg0503[0:16]))
        self._cipher = AES.new(bytes(a ^ b for a, b in zip(enkey1, msg0503[16:32])), AES.MODE_ECB)

    def apply_keystream(self, msg003d: bytes) -> bytearray:
        msg = bytearray(msg003d)
        counter = bytearray(msg[0:16])
        stream = self._cipher.encrypt(bytes(counter))
        pos_stream = 0
        for pos in range(16, len(msg)):
            msg[pos] ^= stream[pos_stream]
            pos_stream += 1
            if pos_stream == 16:
                pos_stream = 0
                for i in range(15, -1, -1):
                    counter[i] = (counter[i] + 1) & 0xFF
                    if counter[i]:
                        break
                stream = self._cipher.encrypt(bytes(counter))
        return msg

    def decrypt(self, msg003d: bytes) -> bytes:
        msg = self.apply_keystream(msg003d)
        return bytes(msg[i + 22] ^ msg[18 + (i & 3)] for i in range(len(msg) - 22))
