from offline_packet_analyzer.parsers.common import MALFORMED, PARSED, UNSUPPORTED
from offline_packet_analyzer.parsers.ethernet import parse_ethernet_frame


def synthetic_ethernet_frame(ethertype: int = 0x0800, payload: bytes = b"payload") -> bytes:
    destination = bytes.fromhex("001122334455")
    source = bytes.fromhex("66778899aabb")
    return destination + source + ethertype.to_bytes(2, "big") + payload


def test_successful_ethernet_parsing() -> None:
    frame = parse_ethernet_frame(synthetic_ethernet_frame(payload=b"abc"))

    assert frame.parse_status == PARSED
    assert frame.destination_mac == "00:11:22:33:44:55"
    assert frame.source_mac == "66:77:88:99:aa:bb"
    assert frame.ethertype == 0x0800
    assert frame.header_length == 14
    assert frame.payload == b"abc"


def test_ethernet_truncation_handling() -> None:
    frame = parse_ethernet_frame(b"\x00" * 13)

    assert frame.parse_status == MALFORMED
    assert frame.error_message is not None


def test_unsupported_ethertype_is_structured_result() -> None:
    frame = parse_ethernet_frame(synthetic_ethernet_frame(ethertype=0x86DD))

    assert frame.parse_status == UNSUPPORTED
    assert frame.ethertype == 0x86DD
    assert frame.error_message == "Unsupported EtherType: 0x86dd"
