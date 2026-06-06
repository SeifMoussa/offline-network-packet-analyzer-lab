from offline_packet_analyzer.parsers.common import MALFORMED, PARSED
from offline_packet_analyzer.parsers.tcp import parse_tcp_segment
from offline_packet_analyzer.parsers.udp import parse_udp_datagram


def synthetic_tcp_segment(data_offset_words: int = 5, payload: bytes = b"") -> bytes:
    header_length = data_offset_words * 4
    header = bytearray(max(header_length, 20))
    header[0:2] = (49152).to_bytes(2, "big")
    header[2:4] = (443).to_bytes(2, "big")
    header[4:8] = (1000).to_bytes(4, "big")
    header[8:12] = (2000).to_bytes(4, "big")
    header[12] = data_offset_words << 4
    header[13] = 0x18
    return bytes(header[:header_length]) + payload


def synthetic_udp_datagram(length: int = 12, payload: bytes = b"data") -> bytes:
    header = bytearray(8)
    header[0:2] = (53000).to_bytes(2, "big")
    header[2:4] = (53).to_bytes(2, "big")
    header[4:6] = length.to_bytes(2, "big")
    header[6:8] = (0).to_bytes(2, "big")
    return bytes(header) + payload


def test_tcp_metadata_parsing() -> None:
    segment = parse_tcp_segment(synthetic_tcp_segment(payload=b"abc"))

    assert segment.parse_status == PARSED
    assert segment.source_port == 49152
    assert segment.destination_port == 443
    assert segment.sequence_number == 1000
    assert segment.acknowledgment_number == 2000
    assert segment.data_offset == 20
    assert segment.flags == 0x18
    assert segment.payload == b"abc"


def test_tcp_invalid_offset_handling() -> None:
    data = bytearray(synthetic_tcp_segment())
    data[12] = 4 << 4

    segment = parse_tcp_segment(bytes(data))

    assert segment.parse_status == MALFORMED
    assert "offset" in str(segment.error_message)


def test_tcp_offset_larger_than_available_handling() -> None:
    data = bytearray(synthetic_tcp_segment())
    data[12] = 6 << 4

    segment = parse_tcp_segment(bytes(data))

    assert segment.parse_status == MALFORMED
    assert "exceeds available bytes" in str(segment.error_message)


def test_tcp_truncated_segment_handling() -> None:
    segment = parse_tcp_segment(b"\x00" * 19)

    assert segment.parse_status == MALFORMED
    assert "20 bytes" in str(segment.error_message)


def test_udp_metadata_parsing() -> None:
    datagram = parse_udp_datagram(synthetic_udp_datagram())

    assert datagram.parse_status == PARSED
    assert datagram.source_port == 53000
    assert datagram.destination_port == 53
    assert datagram.length == 12
    assert datagram.checksum == 0
    assert datagram.payload == b"data"


def test_udp_invalid_length_handling() -> None:
    datagram = parse_udp_datagram(synthetic_udp_datagram(length=7, payload=b""))

    assert datagram.parse_status == MALFORMED
    assert "smaller than 8 bytes" in str(datagram.error_message)


def test_udp_length_larger_than_available_handling() -> None:
    datagram = parse_udp_datagram(synthetic_udp_datagram(length=20, payload=b"data"))

    assert datagram.parse_status == MALFORMED
    assert "exceeds available bytes" in str(datagram.error_message)


def test_udp_truncated_datagram_handling() -> None:
    datagram = parse_udp_datagram(b"\x00" * 7)

    assert datagram.parse_status == MALFORMED
    assert "8 bytes" in str(datagram.error_message)
