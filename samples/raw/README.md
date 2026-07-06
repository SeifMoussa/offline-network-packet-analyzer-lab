# Raw Byte Fixture Policy

The repository does not include binary packet captures, PCAP files, or packet bytes copied from real traffic.

Future raw byte fixtures must be handcrafted in tests only and must remain synthetic. They may be used to exercise:

- Ethernet header parsing
- IPv4 header parsing
- Malformed byte-length handling
- Unsupported EtherType behavior

Raw fixtures must not come from live network traffic, packet captures, production systems, or third-party networks.
