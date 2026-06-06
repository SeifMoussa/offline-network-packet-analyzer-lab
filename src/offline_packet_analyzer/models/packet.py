"""Structured results for synthetic byte parser functions."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class EthernetFrame:
    """Parsed Ethernet frame metadata."""

    parse_status: str
    error_message: str | None = None
    header_length: int = 14
    payload: bytes = b""
    destination_mac: str | None = None
    source_mac: str | None = None
    ethertype: int | None = None


@dataclass(slots=True)
class IPv4Packet:
    """Parsed IPv4 packet metadata."""

    parse_status: str
    error_message: str | None = None
    header_length: int = 0
    payload: bytes = b""
    version: int | None = None
    ihl: int | None = None
    ttl: int | None = None
    protocol: int | None = None
    source_ip: str | None = None
    destination_ip: str | None = None


@dataclass(slots=True)
class TcpSegment:
    """Parsed TCP segment metadata."""

    parse_status: str
    error_message: str | None = None
    header_length: int = 0
    payload: bytes = b""
    source_port: int | None = None
    destination_port: int | None = None
    sequence_number: int | None = None
    acknowledgment_number: int | None = None
    data_offset: int | None = None
    flags: int | None = None


@dataclass(slots=True)
class UdpDatagram:
    """Parsed UDP datagram metadata."""

    parse_status: str
    error_message: str | None = None
    header_length: int = 8
    payload: bytes = b""
    source_port: int | None = None
    destination_port: int | None = None
    length: int | None = None
    checksum: int | None = None
