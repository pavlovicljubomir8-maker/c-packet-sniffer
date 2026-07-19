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
- Parses DNS queries and extracts requested domain names
- Parses HTTP request lines on port 80
- Extracts TLS SNI (server hostname) from HTTPS ClientHello messages

## Example Output

```
[16:54:43] DNS 10.31.186.232:34511 -> 10.31.186.123:53 claude.ai.
[16:59:01] HTTP: GET / HTTP/1.1
[19:21:01] TLS SNI: widget.intercom.io
[16:15:56] TCP 10.31.186.232:47486 -> 23.23.42.90:8883
[16:15:30] UDP 142.251.140.74:443 -> 10.31.186.232:51210
[16:16:17] ICMP 10.31.186.232 -> 10.31.186.123
TCP: 7  UDP: 1  ICMP: 1
Total packets: 12
```

## How It Works

For application-layer protocols, the sniffer inspects packet payloads.
DNS packets (UDP port 53) are parsed to extract the queried domain name, including handling of DNS name compression pointers.
HTTP requests (TCP port 80) have their request line printed.
For HTTPS (TCP port 443), the sniffer parses the TLS ClientHello to extract the SNI hostname — the destination domain, which is sent in plaintext before encryption begins.
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
- DNS, HTTP, and TLS parsing only handle payloads within a single packet; requests split across multiple packets are not reassembled
- TLS SNI extraction does not handle Encrypted ClientHello (ECH), which hides the SNI

## Project Structure

```
sniffer.c
README.md
Makefile
```

## Future Versions

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
