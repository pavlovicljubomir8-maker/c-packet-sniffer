// parse_http.c
#include <stdio.h>
#include <string.h>
#include "parse_http.h"

//"GET " needs the trailing space; the string literal is 4 bytes and the packet has method-plus-space, so comparing against 3-char "GET" would compare its null terminator against the space and never match.
void parse_http_request(unsigned char *buffer, int http_offset, int http_len, const char *timestr) {
    if (http_len > 4 && (
        memcmp(&buffer[http_offset], "GET ", 4) == 0 ||
        memcmp(&buffer[http_offset], "POST", 4) == 0 ||
        memcmp(&buffer[http_offset], "PUT ", 4) == 0 ||
        memcmp(&buffer[http_offset], "HEAD", 4) == 0)) {

        printf("[%s] HTTP: ", timestr);
        for (int i = 0; i < http_len; i++) {
            if (buffer[http_offset + i] == '\r' || buffer[http_offset + i] == '\n') break;
            printf("%c", buffer[http_offset + i]);
        }
        printf("\n");
    }
}
