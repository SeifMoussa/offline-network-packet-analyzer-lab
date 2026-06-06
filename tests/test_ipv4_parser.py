from offline_packet_analyzer.parsers.common import MALFORMED, PARSED
from offline_packet_analyzer.parsers.ipv4 import parse_ipv4_packet


def synthetic_ipv4_packet(
    first_byte: int = 0x45,
    total_length: int = 24,
    protocol: int = 6,
    payload: bytes = b"data",
) -> bytes:
    header = bytearray(20)
    header[0] = first_byte
    header[2:4] = total_length.to_bytes(2, "big")
    header[8] = 64
    header[9] = protocol
    header[12:16] = bytes([192, 0, 2, 10])
    header[16:20] = bytes([198, 51, 100, 20])
    return bytes(header) + payload


def test_successful_ipv4_parsing() -> None:
    packet = parse_ipv4_packet(synthetic_ipv4_packet())

    assert packet.parse_status == PARSED
    assert packet.version == 4
    assert packet.ihl == 20
    assert packet.header_length == 20
    assert packet.ttl == 64
    assert packet.protocol == 6
    assert packet.source_ip == "192.0.2.10"
    assert packet.destination_ip == "198.51.100.20"
    assert packet.payload == b"data"


def test_ipv4_version_ihl_bitmasking() -> None:
    packet = parse_ipv4_packet(synthetic_ipv4_packet(first_byte=0x46, payload=b"1234"))

    assert packet.parse_status == PARSED
    assert packet.version == 4
    assert packet.ihl == 24
    assert packet.payload == b""


def test_ipv4_invalid_version_handling() -> None:
    packet = parse_ipv4_packet(synthetic_ipv4_packet(first_byte=0x65))

    assert packet.parse_status == MALFORMED
    assert packet.version == 6


def test_ipv4_invalid_ihl_handling() -> None:
    packet = parse_ipv4_packet(synthetic_ipv4_packet(first_byte=0x44))

    assert packet.parse_status == MALFORMED
    assert "IHL" in str(packet.error_message)


def test_ipv4_declared_header_length_out_of_bounds_handling() -> None:
    packet = parse_ipv4_packet(synthetic_ipv4_packet(first_byte=0x46, payload=b""))

    assert packet.parse_status == MALFORMED
    assert "exceeds available bytes" in str(packet.error_message)


def test_ipv4_truncated_packet_handling() -> None:
    packet = parse_ipv4_packet(b"\x45" + b"\x00" * 18)

    assert packet.parse_status == MALFORMED
    assert "20 bytes" in str(packet.error_message)
