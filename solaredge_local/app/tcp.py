import logging
import struct
from collections.abc import Callable

log = logging.getLogger(__name__)

TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
MAX_PENDING_SEGMENTS = 50


class _Flow:
    def __init__(self, next_seq: int):
        self.next_seq = next_seq
        self.pending: dict[int, bytes] = {}
        self.buf = bytearray()


class TcpReassembler:
    """Minimal per-direction TCP reassembly of Ethernet/IPv4 frames into ordered byte streams."""

    def __init__(self, on_data: Callable[[bytearray], None]):
        self._on_data = on_data
        self._flows: dict[tuple, _Flow] = {}

    def packet(self, frame: bytes) -> None:
        if len(frame) < 34 or frame[12:14] != b"\x08\x00":
            return
        ip = frame[14:]
        if ip[9] != 6:
            return
        ihl = (ip[0] & 0x0F) * 4
        total = struct.unpack(">H", ip[2:4])[0]
        ip = ip[:total]  # FRITZ!Box pads Ethernet frames to 60 bytes
        tcp = ip[ihl:]
        if len(tcp) < 20:
            return
        sport, dport, seq = struct.unpack(">HHI", tcp[:8])
        flags = tcp[13]
        data = tcp[(tcp[12] >> 4) * 4:]
        key = (bytes(ip[12:16]), sport, bytes(ip[16:20]), dport)

        if flags & TCP_SYN:
            self._flows[key] = _Flow((seq + 1) & 0xFFFFFFFF)
            return
        flow = self._flows.get(key)
        if flow is None:
            flow = self._flows[key] = _Flow(seq)
        if data:
            flow.pending.setdefault(seq, data)
            self._drain(flow)
        if flags & (TCP_FIN | TCP_RST):
            del self._flows[key]

    def _drain(self, flow: _Flow) -> None:
        while self._take_next_segment(flow):
            pass
        if len(flow.pending) > MAX_PENDING_SEGMENTS:
            log.info("TCP gap in inverter stream, skipping ahead")
            flow.next_seq = min(flow.pending)
            while self._take_next_segment(flow):
                pass
        self._on_data(flow.buf)

    @staticmethod
    def _take_next_segment(flow: _Flow) -> bool:
        for seq in sorted(flow.pending):
            data = flow.pending[seq]
            diff = (seq - flow.next_seq) & 0xFFFFFFFF
            if diff == 0:
                flow.buf += data
            elif diff > 0x7FFFFFFF:
                overlap = (flow.next_seq - seq) & 0xFFFFFFFF
                if overlap >= len(data):
                    del flow.pending[seq]
                    return True
                flow.buf += data[overlap:]
            else:
                continue
            flow.next_seq = (seq + len(data)) & 0xFFFFFFFF
            del flow.pending[seq]
            return True
        return False
