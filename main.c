#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <stdint.h>

#include "cli.h"
#include "capture.h"
#include "pcap_writer.h"
#include "stats.h"
#include "parse_dns.h"
#include "parse_tls.h"
#include "parse_http.h"

int main(int argc, char *argv[]) {
    struct sniffer_config cfg;
    int rc = parse_args(argc, argv, &cfg);
    if (rc == 1) return 0;
    if (rc == 2) return 1;

    FILE *pcap_file = NULL;
    if (cfg.pcap_filename != NULL) {
        pcap_file = pcap_open(cfg.pcap_filename);
        if (pcap_file == NULL) { perror("fopen pcap"); return 1; }
    }

    signal(SIGINT, handle_sigint);

    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) { perror("socket"); return 1; }

    unsigned char buffer[65536];
    int tcp_count = 0, udp_count = 0, icmp_count = 0, total_count = 0;
    struct talker_table talkers = { .count = 0 };
    long total_bytes = 0;
    int packets_this_second = 0;
    long bytes_this_second = 0;
    time_t last_rate_print = time(NULL);

    while (running) {
        int bytes = recvfrom(sock, buffer, sizeof(buffer), 0, NULL, NULL);
        if (bytes < 0) { perror("recvfrom"); break; }

        total_count++;
        packets_this_second++;
        bytes_this_second += bytes;
        total_bytes += bytes;

        time_t now = time(NULL);
        struct tm *t = localtime(&now);
        char timestr[16];
        strftime(timestr, sizeof(timestr), "%H:%M:%S", t);

        print_rate_if_new_second(now, &last_rate_print, &packets_this_second, &bytes_this_second);
        // packets come from an untrusted source, so verify a full IP header is present before casting
        if (bytes < 14 + (int)sizeof(struct iphdr)) continue;
        // skipping the 14-byte Ethernet header to reach the IP header.
        struct iphdr *ip = (struct iphdr *)(buffer + 14);
        struct in_addr src, dst;
        src.s_addr = ip->saddr;
        dst.s_addr = ip->daddr;
        // ihl counts 4-byte words, not bytes; usually 20 but can go to 60
        int ip_header_len = ip->ihl * 4;

        if (cfg.filter != 0 && ip->protocol != cfg.filter) continue;
        if (cfg.filter_host != NULL) {
        // compares raw 32-bit addresses rather than strings, sidestepping the same inet_ntoa clobber.
            uint32_t want = inet_addr(cfg.filter_host);
            if (ip->saddr != want && ip->daddr != want) continue;
        }
        // only writes when -w gave a file; passing NULL to fwrite segfaults
        if (pcap_file != NULL) pcap_write_packet(pcap_file, now, buffer, bytes);

        if (ip->protocol == 6) {
            if (bytes < 14 + ip_header_len + (int)sizeof(struct tcphdr)) continue;
            struct tcphdr *tcp = (struct tcphdr *)(buffer + 14 + ip_header_len);
            if (cfg.filter_port != 0 &&
                ntohs(tcp->source) != cfg.filter_port &&
                ntohs(tcp->dest) != cfg.filter_port) continue;

            // inet_ntoa returns a shared static buffer, so two calls in one printf would clobber the first
            printf("[%s] TCP %s:%d -> ", timestr, inet_ntoa(src), ntohs(tcp->source));
            printf("%s:%d\n", inet_ntoa(dst), ntohs(tcp->dest));
            tcp_count++;
            // same 4-byte-word encoding as ihl; needed because the TCP header is variable-length
            int tcp_header_len = tcp->doff * 4;

            if (ntohs(tcp->source) == 80 || ntohs(tcp->dest) == 80) {
                int http_offset = 14 + ip_header_len + tcp_header_len;
                parse_http_request(buffer, http_offset, bytes - http_offset, timestr);
            }
            if (ntohs(tcp->source) == 443 || ntohs(tcp->dest) == 443) {
                int tls_offset = 14 + ip_header_len + tcp_header_len;
                int tls_len = bytes - tls_offset;
            // record type 22 is a handshake
                if (tls_len > 5 && buffer[tls_offset] == 22 && buffer[tls_offset + 5] == 1)
                    parse_tls_sni(buffer, bytes, tls_offset, timestr);
            }
        }
        else if (ip->protocol == 17) {
            if (bytes < 14 + ip_header_len + (int)sizeof(struct udphdr)) continue;
            struct udphdr *udp = (struct udphdr *)(buffer + 14 + ip_header_len);
            if (cfg.filter_port != 0 &&
                ntohs(udp->source) != cfg.filter_port &&
                ntohs(udp->dest) != cfg.filter_port) continue;
            udp_count++;

            if (ntohs(udp->source) == 53 || ntohs(udp->dest) == 53) {
                int dns_offset = 14 + ip_header_len + 8;
            // DNS header is 12 bytes; guards the name parse that starts right after it
                if (bytes - dns_offset < 12) continue;
                printf("[%s] DNS %s:%d -> ", timestr, inet_ntoa(src), ntohs(udp->source));
                printf("%s:%d ", inet_ntoa(dst), ntohs(udp->dest));
                parse_dns_name(buffer, bytes, dns_offset + 12, dns_offset);
            } else {
                printf("[%s] UDP %s:%d -> ", timestr, inet_ntoa(src), ntohs(udp->source));
                printf("%s:%d\n", inet_ntoa(dst), ntohs(udp->dest));
            }
        }
        else if (ip->protocol == 1) {
            printf("[%s] ICMP %s -> ", timestr, inet_ntoa(src));
            printf("%s\n", inet_ntoa(dst));
            icmp_count++;
        }
        // source only, which is why the local machine dominates the list
        record_talker(&talkers, ip->saddr);
    }

    close(sock);
    if (pcap_file != NULL) fclose(pcap_file);

    print_top_talkers(&talkers);
    printf("TCP: %d UDP: %d ICMP: %d\n", tcp_count, udp_count, icmp_count);
    printf("Total packets: %d\n", total_count);
    printf("\nShutting down. Bye until next time.\n");
    return 0;
}
