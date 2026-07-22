// parse_http.h owns printing the request line from an HTTP payload
#ifndef PARSE_HTTP_H
#define PARSE_HTTP_H
void parse_http_request(unsigned char *buffer, int http_offset, int http_len, const char *timestr);
#endif
