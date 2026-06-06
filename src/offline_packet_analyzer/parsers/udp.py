"""UDP metadata parser for handcrafted synthetic byte fixtures."""

from __future__ import annotations

import struct

from offline_packet_analyzer.models.packet import UdpDatagram
from offline_packet_analyzer.parsers.common import MALFORMED, PARSED

UDP_HEADER_LENGTH = 8


def parse_udp_datagram(udp_data: bytes) -> UdpDatagram:
    """Parse UDP metadata from bytes supplied by the caller."""
    if len(udp_data) < UDP_HEADER_LENGTH:
        return UdpDatagram(
            parse_status=MALFORMED,
            error_message="UDP datagram requires at least 8 bytes",
        )

    source_port, destination_port, length, checksum = struct.unpack("!HHHH", udp_data[:8])

    if length < UDP_HEADER_LENGTH:
        return UdpDatagram(
            parse_status=MALFORMED,
            error_message="UDP length is smaller than 8 bytes",
            source_port=source_port,
            destination_port=destination_port,
            length=length,
            checksum=checksum,
        )
    if len(udp_data) < length:
        return UdpDatagram(
            parse_status=MALFORMED,
            error_message="UDP length exceeds available bytes",
            source_port=source_port,
            destination_port=destination_port,
            length=length,
            checksum=checksum,
        )

    return UdpDatagram(
        parse_status=PARSED,
        header_length=UDP_HEADER_LENGTH,
        payload=udp_data[UDP_HEADER_LENGTH:length],
        source_port=source_port,
        destination_port=destination_port,
        length=length,
        checksum=checksum,
    )
