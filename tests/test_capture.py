import pytest

from app.pcap import PcapFormatError, PcapStreamParser
from app.solaredge import FN_KEEPALIVE, build_message, split_messages
from app.tcp import TCP_SYN, TcpReassembler
from helpers import INVERTER, SERVER, ethernet_tcp_frame, pcap_stream

INV_IP, SRV_IP = bytes([192, 168, 188, 31]), bytes([167, 94, 174, 2])


def frame(seq, data, flags=0x18):
    return ethernet_tcp_frame(INV_IP, SRV_IP, 40000, 22222, seq, flags, data)


@pytest.mark.parametrize("modified", [True, False])
def test_pcap_parser_handles_byte_by_byte_feeding(modified):
    frames = [b"\x01" * 60, b"\x02" * 100]
    stream = pcap_stream(frames, modified=modified)
    parser = PcapStreamParser()

    out = [f for i in range(len(stream)) for f in parser.feed(stream[i:i + 1])]

    assert out == frames


def test_pcap_parser_rejects_unknown_magic():
    with pytest.raises(PcapFormatError):
        list(PcapStreamParser().feed(b"\x00" * 24))


class Collector:
    def __init__(self):
        self.payloads = []

    def __call__(self, buf):
        self.payloads += [p for _, p in split_messages(buf)]


def test_tcp_reassembly_reorders_segments_and_trims_ethernet_padding():
    msg = build_message(1, INVERTER, SERVER, FN_KEEPALIVE, b"hello world")
    a, b, c = msg[:5], msg[5:12], msg[12:]
    sink = Collector()
    tcp = TcpReassembler(sink)

    tcp.packet(frame(999, b"", flags=TCP_SYN))
    tcp.packet(frame(1000 + len(a), b))
    tcp.packet(frame(1000 + len(a) + len(b), c))
    tcp.packet(frame(1000, a))

    assert sink.payloads == [b"hello world"]


def test_tcp_reassembly_ignores_retransmission():
    msg = build_message(1, INVERTER, SERVER, FN_KEEPALIVE, b"x")
    sink = Collector()
    tcp = TcpReassembler(sink)

    tcp.packet(frame(1000, msg))
    tcp.packet(frame(1000, msg))

    assert sink.payloads == [b"x"]


def test_tcp_reassembly_starts_mid_stream_without_syn():
    msg = build_message(1, INVERTER, SERVER, FN_KEEPALIVE, b"mid")
    sink = Collector()

    TcpReassembler(sink).packet(frame(123456, b"junk" + msg))

    assert sink.payloads == [b"mid"]
