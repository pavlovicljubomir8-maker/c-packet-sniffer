// parse_dns.h owns extracting the queried domain from a DNS payload
#ifndef PARSE_DNS_H
#define PARSE_DNS_H
void parse_dns_name(unsigned char *buffer, int bytes, int start, int dns_start);
#endif

