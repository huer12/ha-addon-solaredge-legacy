import os

from app.main import run_replay
from app.solaredge import FN_SESSION_KEY, FN_TELEMETRY, build_message
from app.tcp import TCP_SYN
from helpers import (INVERTER, SERVER, encrypted_message, ethernet_tcp_frame, inverter3_block,
                     optimizer_block, pcap_stream)

INV_IP, SRV_IP = bytes([192, 168, 188, 31]), bytes([167, 94, 174, 2])


def test_replay_decodes_full_pipeline_from_pcap_file(tmp_path, capsys):
    # Arrange
    key, msg0503 = os.urandom(16), os.urandom(34)
    telemetry = build_message(5, INVERTER, SERVER, FN_TELEMETRY,
                              inverter3_block(0x7F012345, Mode=5, Pactive1=100.0, Pactive2=100.0, Pactive3=100.0)
                              + optimizer_block(0x1012ABCD, 30, 20, 1, 5, 20))
    stream = build_message(1, INVERTER, SERVER, FN_SESSION_KEY, msg0503) + encrypted_message(key, msg0503, telemetry)
    seq = 5000
    frames = [ethernet_tcp_frame(INV_IP, SRV_IP, 40000, 22222, seq - 1, TCP_SYN, b"")]
    for i in range(0, len(stream), 100):
        frames.append(ethernet_tcp_frame(INV_IP, SRV_IP, 40000, 22222, seq + i, 0x18, stream[i:i + 100]))
    capture = tmp_path / "test.eth"
    capture.write_bytes(pcap_stream(frames))

    # Act
    run_replay(capture, key, details=False)

    # Assert
    out = capsys.readouterr().out
    assert 'INVERTER 7F012345 {"mode": 5, "status": "Producing"' in out
    assert '"ac_power": 300.0' in out
    assert "OPTIMIZER 1012ABCD" in out
