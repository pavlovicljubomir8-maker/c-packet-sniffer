// pcap_writer.h owns writing capture files in PCAP format (the layout Wireshark/tcpdump read)
#ifndef PCAP_WRITER_H
#define PCAP_WRITER_H
#include <stdio.h>
#include <stdint.h>
#include <time.h>
//written once, describes the whole file
struct pcap_global_header {
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t  thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
};
//written before every packet, its timestamp and length
struct pcap_packet_header {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
};

// Opens filename, writes the global header. Returns NULL on failure
// (errno is preserved so the caller can perror() immediately after).
FILE *pcap_open(const char *filename);
void pcap_write_packet(FILE *pcap_file, time_t now, const unsigned char *buffer, int bytes);
#endif
