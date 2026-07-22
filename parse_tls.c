// parse_tls.c  record header, handshake header, version, random, then three variable-length fields each read-length-then-skip, to reach the extensions
#include <stdio.h>
#include "parse_tls.h"

void parse_tls_sni(unsigned char *buffer, int bytes, int tls_offset, char *timestr) {
    int pos = tls_offset;
    pos += 5 + 4;
    pos += 2;
    pos += 32;
    if (pos + 1 > bytes) return;
    int session_id_len = buffer[pos];
    pos += 1 + session_id_len;
    if (pos + 2 > bytes) return;
    int cipher_len = (buffer[pos] << 8) | buffer[pos + 1];
    pos += 2 + cipher_len;
    if (pos + 1 > bytes) return;
    int com_len = buffer[pos];
    pos += 1 + com_len;
    if (pos + 2 > bytes) return;
    pos += 2;

    while (pos + 4 <= bytes) {
        int ext_type = (buffer[pos] << 8) | buffer[pos + 1];
        int ext_len  = (buffer[pos + 2] << 8) | buffer[pos + 3];
        pos += 4;
// SNI extension
        if (ext_type == 0) {
// every length is attacker-controlled, so bounds-check before each read.
            if (pos + 5 > bytes) return;
            int name_len = (buffer[pos + 3] << 8) | buffer[pos + 4];
            int name_start = pos + 5;
            if (name_start + name_len > bytes) return;
            printf("[%s] TLS SNI: ", timestr);
            for (int i = 0; i < name_len; i++) printf("%c", buffer[name_start + i]);
            printf("\n");
            return;
        }
        pos += ext_len;
    }
}
