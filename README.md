# C Packet Sniffer

A packet sniffer written in C using raw sockets on Linux. The project captures live network traffic and parses Ethernet, IPv4, TCP, UDP, and ICMP packets.

## Features

- Captures live packets using Linux raw sockets
- Parses IPv4 headers
- Identifies TCP, UDP, and ICMP traffic
- Displays source and destination IP addresses
- Displays source and destination ports
- Graceful shutdown with Ctrl+C

## Example Output

```
TCP 192.168.1.15:52874 -> 142.250.184.78:443
UDP 192.168.1.15:5353 -> 224.0.0.251:5353
ICMP 8.8.8.8 -> 192.168.1.15
```

## How It Works

A raw socket is created using `socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))`. The program waits for packets using `recvfrom()`.

Ethernet headers (14 bytes) are skipped, and the remaining bytes are interpreted as an IPv4 header. The protocol field determines whether the packet contains TCP, UDP, or ICMP. TCP and UDP headers are parsed to extract port numbers, and the packet information is printed to the terminal.

## Safety

Network packets originate from untrusted sources. Before interpreting raw bytes as protocol headers, the program verifies that enough data has been received.

For example:

- Verifies that an entire IPv4 header is present before accessing its fields
- Uses the IPv4 Internet Header Length (IHL) field to correctly locate the transport-layer header
- Performs protocol-specific bounds checks before parsing TCP or UDP headers

These checks prevent out-of-bounds memory reads and improve parser robustness. The program has been verified with Valgrind under live traffic with no memory errors reported.

## Requirements

- Linux
- GCC
- Root privileges (CAP_NET_RAW)

## Build

```bash
gcc -Wall sniffer.c -o sniffer
```

## Running

Raw sockets require root privileges.

```bash
sudo ./sniffer
```

Stop the program with `Ctrl+C`.

## Limitations

- IPv4 only (no IPv6 support)
- No packet filtering — all traffic is displayed
- Linux only (uses `AF_PACKET`)
- Shutdown depends on `recvfrom()` returning; on a silent network there may be a brief delay before the program exits

## Project Structure

```
sniffer.c
README.md
```

## Future Versions

**v2**
- Command-line packet filtering
- Packet statistics
- Interface selection

**v3**
- DNS parsing
- HTTP request parsing
- TLS ClientHello information

**v4**
- PCAP export
- Configuration file
- Logging
- Improved command-line interface

**v5**
- Multi-threaded packet processing
- TCP flow tracking
- Basic TCP stream reassembly
- Plugin architecture for protocol decoders

## License

This project is released under the MIT License.
