"""IPv4 parser for handcrafted synthetic byte fixtures."""

from __future__ import annotations

from offline_packet_analyzer.models.packet import IPv4Packet
from offline_packet_analyzer.parsers.common import MALFORMED, PARSED, format_ipv4

MIN_IPV4_HEADER_LENGTH = 20


def parse_ipv4_packet(ip_data: bytes) -> IPv4Packet:
    """Parse IPv4 metadata from bytes supplied by the caller."""
    if len(ip_data) < MIN_IPV4_HEADER_LENGTH:
        return IPv4Packet(
            parse_status=MALFORMED,
            error_message="IPv4 packet requires at least 20 bytes",
        )

    version = ip_data[0] >> 4
    ihl_words = ip_data[0] & 0x0F
    header_length = ihl_words * 4

    if version != 4:
        return IPv4Packet(
            parse_status=MALFORMED,
            error_message=f"Unsupported IP version: {version}",
            version=version,
            ihl=header_length,
            header_length=header_length,
        )
    if header_length < MIN_IPV4_HEADER_LENGTH:
        return IPv4Packet(
            parse_status=MALFORMED,
            error_message="IPv4 IHL is smaller than 20 bytes",
            version=version,
            ihl=header_length,
            header_length=header_length,
        )
    if len(ip_data) < header_length:
        return IPv4Packet(
            parse_status=MALFORMED,
            error_message="IPv4 header length exceeds available bytes",
            version=version,
            ihl=header_length,
            header_length=header_length,
        )

    ttl = ip_data[8]
    protocol = ip_data[9]
    source_ip = format_ipv4(ip_data[12:16])
    destination_ip = format_ipv4(ip_data[16:20])

    return IPv4Packet(
        parse_status=PARSED,
        header_length=header_length,
        payload=ip_data[header_length:],
        version=version,
        ihl=header_length,
        ttl=ttl,
        protocol=protocol,
        source_ip=source_ip,
        destination_ip=destination_ip,
    )
