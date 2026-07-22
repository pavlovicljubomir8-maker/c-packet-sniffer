// parse_dns.c
#include <stdio.h>
#include "parse_dns.h"

void parse_dns_name(unsigned char *buffer, int bytes, int start, int dns_start) {
    int position = start;
    int jumps = 0;
    while (position < bytes) {
        int len = buffer[position];
        if (len == 0) break;
        if (len >= 192) {
            if (position + 1 >= bytes) break;
            int offset = ((len & 0x3F) << 8) | buffer[position + 1];
            if (dns_start + offset >= bytes) break;
            jumps++;
            if (jumps > 10) break;
            position = dns_start + offset;
            continue;
        }
        if (position + 1 + len > bytes) break;
        for (int i = 0; i < len; i++) printf("%c", buffer[position + 1 + i]);
        printf(".");
        position += 1 + len;
    }
    printf("\n");
}

