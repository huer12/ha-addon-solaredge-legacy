import struct
from collections.abc import Iterator

GLOBAL_HEADER_LEN = 24
# FRITZ!Box streams "modified pcap" (Kuznetzov) with 24-byte record headers instead of 16.
RECORD_LEN_BY_MAGIC = {
    b"\xa1\xb2\xcd\x34": (">", 24),
    b"\x34\xcd\xb2\xa1": ("<", 24),
    b"\xa1\xb2\xc3\xd4": (">", 16),
    b"\xd4\xc3\xb2\xa1": ("<", 16),
}


class PcapFormatError(ValueError):
    pass


class PcapStreamParser:
    """Incremental pcap parser: feed arbitrary chunks, get complete frames back."""

    def __init__(self):
        self._buf = bytearray()
        self._endian: str | None = None
        self._record_len = 0
        self.received_bytes = 0

    def feed(self, chunk: bytes) -> Iterator[bytes]:
        self._buf += chunk
        self.received_bytes += len(chunk)
        if self._endian is None:
            if len(self._buf) < GLOBAL_HEADER_LEN:
                return
            magic = bytes(self._buf[:4])
            if magic not in RECORD_LEN_BY_MAGIC:
                raise PcapFormatError("Unknown capture format, magic %s" % magic.hex())
            self._endian, self._record_len = RECORD_LEN_BY_MAGIC[magic]
            del self._buf[:GLOBAL_HEADER_LEN]
        while len(self._buf) >= self._record_len:
            incl_len = struct.unpack(self._endian + "I", self._buf[8:12])[0]
            end = self._record_len + incl_len
            if len(self._buf) < end:
                return
            frame = bytes(self._buf[self._record_len:end])
            del self._buf[:end]
            yield frame
