"""Ethernet parser for handcrafted synthetic byte fixtures."""

from __future__ import annotations

import struct

from offline_packet_analyzer.models.packet import EthernetFrame
from offline_packet_analyzer.parsers.common import MALFORMED, PARSED, UNSUPPORTED, format_mac

ETHERNET_HEADER_LENGTH = 14
SUPPORTED_ETHERTYPES = frozenset({0x0800})


def parse_ethernet_frame(raw_data: bytes) -> EthernetFrame:
    """Parse Ethernet metadata from bytes supplied by the caller."""
    if len(raw_data) < ETHERNET_HEADER_LENGTH:
        return EthernetFrame(
            parse_status=MALFORMED,
            error_message="Ethernet frame requires at least 14 bytes",
        )

    destination_raw, source_raw, ethertype = struct.unpack("!6s6sH", raw_data[:14])
    payload = raw_data[ETHERNET_HEADER_LENGTH:]
    status = PARSED if ethertype in SUPPORTED_ETHERTYPES else UNSUPPORTED
    error = None if status == PARSED else f"Unsupported EtherType: 0x{ethertype:04x}"

    return EthernetFrame(
        parse_status=status,
        error_message=error,
        header_length=ETHERNET_HEADER_LENGTH,
        payload=payload,
        destination_mac=format_mac(destination_raw),
        source_mac=format_mac(source_raw),
        ethertype=ethertype,
    )
