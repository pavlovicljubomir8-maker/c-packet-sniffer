# C Packet Sniffer

A packet sniffer written in C using raw sockets on Linux. The project captures live network traffic and parses Ethernet, IPv4, TCP, UDP, and ICMP packets.

## Features

- Captures live packets using Linux raw sockets
- Parses IPv4 headers
- Identifies TCP, UDP, and ICMP traffic
- Displays source and destination IP addresses
- Displays source and destination ports
- Graceful shutdown with Ctrl+C
- Filtering for scepific protocol
- Statistics shows you chosen protocol count 
- Each packet is timestamped

## Example Output

```
[16:15:56] TCP 10.31.186.232:47486 -> 23.23.42.90:8883
[16:15:30] UDP 142.251.140.74:443 -> 10.31.186.232:51210
[16:16:17] ICMP 10.31.186.232 -> 10.31.186.123
TCP: 5  UDP: 0  ICMP: 0
Total packets: 8
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
make
```

## Running

Raw sockets require root privileges.

```bash
sudo ./sniffer
```
```bash
sudo ./sniffer [tcp|udp|icmp|--help]
```

Stop the program with `Ctrl+C`.

## Limitations

- IPv4 only (no IPv6 support)
- Linux only (uses `AF_PACKET`)
- Shutdown depends on `recvfrom()` returning; on a silent network there may be a brief delay before the program exits
- Filtering is protocol only

## Project Structure

```
sniffer.c
README.md
Makefile
```

## Future Versions

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
