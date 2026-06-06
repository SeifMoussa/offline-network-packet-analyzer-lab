"""TCP metadata parser for handcrafted synthetic byte fixtures."""

from __future__ import annotations

import struct

from offline_packet_analyzer.models.packet import TcpSegment
from offline_packet_analyzer.parsers.common import MALFORMED, PARSED

MIN_TCP_HEADER_LENGTH = 20


def parse_tcp_segment(tcp_data: bytes) -> TcpSegment:
    """Parse TCP metadata from bytes supplied by the caller."""
    if len(tcp_data) < MIN_TCP_HEADER_LENGTH:
        return TcpSegment(
            parse_status=MALFORMED,
            error_message="TCP segment requires at least 20 bytes",
        )

    source_port, destination_port, sequence_number, acknowledgment_number = struct.unpack(
        "!HHII", tcp_data[:12]
    )
    data_offset = (tcp_data[12] >> 4) * 4
    flags = tcp_data[13]

    if data_offset < MIN_TCP_HEADER_LENGTH:
        return TcpSegment(
            parse_status=MALFORMED,
            error_message="TCP data offset is smaller than 20 bytes",
            source_port=source_port,
            destination_port=destination_port,
            sequence_number=sequence_number,
            acknowledgment_number=acknowledgment_number,
            data_offset=data_offset,
            flags=flags,
        )
    if len(tcp_data) < data_offset:
        return TcpSegment(
            parse_status=MALFORMED,
            error_message="TCP data offset exceeds available bytes",
            source_port=source_port,
            destination_port=destination_port,
            sequence_number=sequence_number,
            acknowledgment_number=acknowledgment_number,
            data_offset=data_offset,
            flags=flags,
        )

    return TcpSegment(
        parse_status=PARSED,
        header_length=data_offset,
        payload=tcp_data[data_offset:],
        source_port=source_port,
        destination_port=destination_port,
        sequence_number=sequence_number,
        acknowledgment_number=acknowledgment_number,
        data_offset=data_offset,
        flags=flags,
    )
