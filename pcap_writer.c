// pcap_writer.c
#include "pcap_writer.h"

FILE *pcap_open(const char *filename) {
    FILE *f = fopen(filename, "wb");
    if (f == NULL) return NULL;

    struct pcap_global_header gh;
    gh.magic_number  = 0xa1b2c3d4;
    gh.version_major = 2;
    gh.version_minor = 4;
    gh.thiszone      = 0;
    gh.sigfigs       = 0;
    gh.snaplen       = 65535;
    gh.network       = 1;
    fwrite(&gh, sizeof(gh), 1, f);
    return f;
}

void pcap_write_packet(FILE *pcap_file, time_t now, const unsigned char *buffer, int bytes) {
    struct pcap_packet_header ph;
    ph.ts_sec   = (uint32_t)now;
    ph.ts_usec  = 0;
    ph.incl_len = bytes;
    ph.orig_len = bytes;
    fwrite(&ph, sizeof(ph), 1, pcap_file);
    fwrite(buffer, bytes, 1, pcap_file);
}
