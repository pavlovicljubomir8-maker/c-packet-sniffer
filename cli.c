// cli.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cli.h"

int parse_args(int argc, char *argv[], struct sniffer_config *cfg) {
    cfg->filter = 0;
    cfg->pcap_filename = NULL;
    cfg->filter_port = 0;
    cfg->filter_host = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0) {
            printf("Usage: %s [tcp|udp|icmp] [-w file.pcap] [--port N] [--host IP]\n", argv[0]);
            printf("  No argument: capture all protocols\n");
            return 1;
        }
        else if (strcmp(argv[i], "-w") == 0) {
            if (i + 1 < argc) { cfg->pcap_filename = argv[i + 1]; i++; }
            else { printf("-w requires a filename\n"); return 2; }
        }
        else if (strcmp(argv[i], "tcp") == 0)  cfg->filter = 6;
        else if (strcmp(argv[i], "udp") == 0)  cfg->filter = 17;
        else if (strcmp(argv[i], "icmp") == 0) cfg->filter = 1;
        else if (strcmp(argv[i], "--port") == 0) {
            if (i + 1 < argc) { cfg->filter_port = atoi(argv[i + 1]); i++; }
            else { printf("--port requires a number\n"); return 2; }
        }
        else if (strcmp(argv[i], "--host") == 0) {
            if (i + 1 < argc) { cfg->filter_host = argv[i + 1]; i++; }
            else { printf("--host requires an IP address\n"); return 2; }
        }
        else {
            printf("Unknown argument: %s\n", argv[i]);
            return 2;
        }
    }
    return 0;
}
