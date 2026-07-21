#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

volatile sig_atomic_t running = 1;

//Sets a flag instead of terminating imediatelly so the main loop can exit cleanly.
void handle_sigint(int sig) {
    (void)sig;
    running = 0;
}

void parse_dns_name(unsigned char *buffer, int bytes, int start, int dns_start) {
    int position = start;
    int jumps = 0;

    while (position < bytes) {

        int len = buffer[position];
        if (len == 0)break;

        if (len >= 192){
            if (position + 1 >= bytes) break;
            int offset = ((len & 0x3F) << 8) | buffer[position + 1];
            if (dns_start + offset >= bytes) break;
            jumps ++;
            if (jumps > 10) break;
            position = dns_start + offset;
            continue;
        }

        if (position + 1 + len > bytes) break;
        for (int i = 0; i < len; i++) {
        printf("%c", buffer[position + 1 + i]);
        }
        printf(".");
        position += 1 + len;
    }    

    printf("\n");
}

void parse_tls_sni(unsigned char *buffer, int bytes, int tls_offset, char *timestr){
    int pos = tls_offset;

    pos += 5 + 4;
    pos += 2;
    pos += 32;
    if (pos + 1 >bytes) return;
    int session_id_len = buffer[pos];
    pos += 1 + session_id_len;

    if (pos + 2 > bytes) return;
    int cipher_len = (buffer[pos] << 8) | buffer[pos + 1];
    pos += 2 + cipher_len;

    if (pos + 1 > bytes) return;
    int com_len = buffer[pos];
    pos += 1 + com_len;

    if(pos + 2 > bytes) return;
    pos += 2;

    while (pos + 4 <= bytes) {
        int ext_type = (buffer[pos] << 8) | buffer[pos + 1];
        int ext_len = (buffer[pos + 2] << 8) | buffer[pos + 3];
        pos += 4;
        if (ext_type == 0) {
            if (pos + 5 > bytes) return;
            int name_len = (buffer[pos + 3] << 8) | buffer[pos + 4];
            int name_start = pos + 5;

            if (name_start + name_len > bytes) return;

            printf("[%s] TLS SNI: ", timestr);
            for (int i = 0; i < name_len; i++){
                printf("%c", buffer[name_start + i]);
            }
            printf("\n");
            return;
        }
        pos += ext_len;
    }
}
// Describes the whole capture
struct pcap_global_header {
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
};
//Written before each capture
struct pcap_packet_header {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
};

struct ip_counter {
    uint32_t ip;
    int count;
};

int main (int argc, char *argv[]) {
	int filter = 0;
    char *pcap_filename = NULL;
    int filter_port = 0;
    char *filter_host = NULL;



    for (int i = 1; i < argc; i++){
        if (strcmp(argv[i], "--help") == 0){
            printf("Usage: %s [tcp|udp|icmp][-w file.pcap]\n", argv[0]);
            printf(" No argument: capture all protocols\n");
            return 0;
        }
        else if (strcmp(argv[i], "-w") == 0){
            if (i + 1 < argc){
//Grabs next argument as value                
                pcap_filename = argv[i + 1];
                i++;
            } else{
                printf("-w requires a filename\n");
                return 1;
            }
        }
        else if (strcmp(argv[i], "tcp") == 0 ) filter = 6;
        else if (strcmp(argv[i], "udp") == 0 ) filter = 17;
        else if (strcmp(argv[i], "icmp") == 0 ) filter = 1;
        else if (strcmp(argv[i], "--port") == 0) {
            if (i + 1 < argc){
                filter_port = atoi(argv[i + 1]);
                i++;
            } else {
                printf("--port requires a number\n");
                return 1;
            }
        }
        else if (strcmp(argv[i], "--host") == 0) {
            if (i + 1 < argc) {
                filter_host = argv[i + 1];
                i++;
            } else {
                printf("--host requires an IP address\n");
                return 1;
            }
        }
        else {
            printf("Unknown argument: %s\n", argv[i]);
            return 1;
        } 
    }

    FILE *pcap_file = NULL;
    if (pcap_filename != NULL) {
        pcap_file = fopen(pcap_filename, "wb");
        if (pcap_file == NULL) {
            perror("fopen pcap");
            return 1;
        }
    

        struct pcap_global_header gh;
//Marks file as PCAP        
        gh.magic_number  = 0xa1b2c3d4;
        gh.version_major = 2;
        gh.version_minor = 4;
        gh.thiszone      = 0;
        gh.sigfigs       = 0;
        gh.snaplen       = 65535;
        gh.network       = 1;

        fwrite(&gh, sizeof(gh), 1, pcap_file);
    }
		
    signal(SIGINT, handle_sigint);

    // Create raw socket
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        perror("socket");
        return 1;
    }

    unsigned char buffer[65536];

    int tcp_count = 0;
    int udp_count = 0;
    int icmp_count = 0;
    int total_count = 0;
    struct ip_counter talkers[1000];
    int talker_count = 0;
    long total_bytes = 0;
    int packets_this_second = 0;
    long bytes_this_second = 0;
    time_t last_rate_print = time(NULL);

//Capture packet untill Ctrl+c is pressed	
    while (running) {
        int bytes = recvfrom(sock, buffer, sizeof(buffer), 0, NULL, NULL);
        if (bytes < 0) {
            perror("recvfrom");
            break;
        }

        total_count ++; 
        packets_this_second++;
        bytes_this_second += bytes;
        total_bytes += bytes;

		
		time_t now = time(NULL);
		struct tm *t = localtime(&now);
		char timestr[16];
		strftime(timestr, sizeof(timestr), "%H:%M:%S", t);
//print the per second rate and reset counters
        if (now > last_rate_print) {
            printf(">>> Rate: %d packets/sec, %ld bytes/sec\n",
                packets_this_second, bytes_this_second);
            packets_this_second = 0;
            bytes_this_second = 0;
            last_rate_print = now;
        }
        
//Verify enough bytes were received for a complete IPv4 header
        if (bytes < 14 + (int)sizeof(struct iphdr)) continue;
//Skip 14-byte Ethernet header        
        struct iphdr *ip = (struct iphdr *)(buffer + 14);
        struct in_addr src, dst;
        src.s_addr = ip->saddr;
        dst.s_addr = ip->daddr;

//ihl counts 4 byte words, not bytes - headers are usually 20 but can go up to 60
        int ip_header_len = ip-> ihl *4;

//Skip packets that do not match selected filter
		if (filter != 0 && ip->protocol != filter) continue;
        if (filter_host != NULL){
//Compare ra 32 bit addresses
            uint32_t want = inet_addr(filter_host);
            if (ip->saddr != want && ip->daddr != want) continue;
        }
//Only write if -w gave a file
        if (pcap_file != NULL) {
            struct pcap_packet_header ph;
            ph.ts_sec   = now;
            ph.ts_usec  = 0;
            ph.incl_len = bytes;
            ph.orig_len = bytes;
            fwrite(&ph, sizeof(ph), 1, pcap_file);
            fwrite(buffer, bytes, 1, pcap_file);
        }

		
        if (ip->protocol == 6){
            if(bytes < 14 + ip_header_len + (int)sizeof(struct tcphdr)) continue;
            struct tcphdr *tcp = (struct tcphdr *)(buffer + 14 + ip_header_len);
            if (filter_port != 0 &&
                ntohs(tcp->source) != filter_port &&
                ntohs(tcp->dest) != filter_port) continue;
//inet_ntoa returns a shared static buffer, two calls in one printf would clober the first            
             printf("[%s] TCP %s:%d -> ", timestr, inet_ntoa(src), ntohs(tcp->source));
             printf("%s:%d\n", inet_ntoa(dst), ntohs(tcp->dest));
             tcp_count ++;

//HTTP Parser
            if(ntohs(tcp->source) == 80 || ntohs(tcp->dest) == 80){
                int tcp_header_len = tcp->doff * 4;
                int http_offset = 14 + ip_header_len + tcp_header_len;
                int http_len = bytes - http_offset;

                if (http_len > 4 && (
                    memcmp(&buffer[http_offset], "GET ", 4) == 0 ||
                    memcmp(&buffer[http_offset], "POST", 4) == 0 ||
                    memcmp(&buffer[http_offset], "PUT ", 4) == 0 ||
                    memcmp(&buffer[http_offset], "HEAD", 4) == 0)) {

                        printf("[%s] HTTP: ", timestr);
                        for (int i = 0; i < http_len; i++){
                            if (buffer[http_offset + i] == '\r' || buffer[http_offset + i] == '\n') break;
                            printf("%c", buffer[http_offset + i]);
                        }
                        printf("\n");
                    }
            } 
// TLS Parser
            if(ntohs(tcp->source) == 443 || ntohs(tcp->dest) == 443){
                int tcp_header_len = tcp->doff * 4;
                int tls_offset = 14 + ip_header_len + tcp_header_len;
                int tls_len = bytes - tls_offset;

                if (tls_len > 5 && buffer[tls_offset] == 22) {
                        parse_tls_sni(buffer, bytes, tls_offset, timestr);                   
                }
            }
        }
        else if (ip->protocol == 17){
            if (bytes < 14 + ip_header_len + (int)sizeof(struct udphdr)) continue;
            struct udphdr *udp = (struct udphdr *)(buffer + 14 + ip_header_len);
            if (filter_port != 0 &&
                ntohs(udp->source) != filter_port &&
                ntohs(udp->dest) != filter_port) continue;
            udp_count ++;
           
            if (ntohs(udp->source) == 53 || ntohs(udp->dest) == 53) {
                int dns_offset = 14 + ip_header_len +8;
                int dns_len = bytes - dns_offset;
                if (dns_len < 12) continue;
                printf("[%s] DNS %s:%d -> ", timestr, inet_ntoa(src), ntohs(udp->source));
                printf("%s:%d ", inet_ntoa(dst), ntohs(udp-> dest));
                parse_dns_name(buffer, bytes, dns_offset + 12, dns_offset);
            }
            else {
                 printf("[%s] UDP %s:%d -> ", timestr,  inet_ntoa(src), ntohs(udp->source));
                 printf("%s:%d\n", inet_ntoa(dst), ntohs(udp->dest));
            }
            
        }
        else if( ip->protocol == 1) {
        printf("[%s] ICMP %s -> ", timestr, inet_ntoa(src));
        printf("%s\n", inet_ntoa(dst));
        icmp_count ++;
        }
//Linear search for source IP
        int found = 0;
        for (int i = 0; i < talker_count; i++){
            if (talkers[i].ip == ip->saddr){
                talkers[i].count++;
                found = 1;
                break;
            }
        }
        if (!found && talker_count < 1000){
            talkers[talker_count].ip = ip->saddr;
            talkers[talker_count].count = 1;
            talker_count++;
        }
    }
    close(sock);
    if (pcap_file != NULL) fclose(pcap_file);
//Print statistic
    for (int i = 0; i < talker_count; i++){
//Sort by count, descending        
        for (int j = i + 1; j< talker_count; j++){
            if (talkers[j].count > talkers[i].count){
                struct ip_counter tmp = talkers[i];
                talkers[i] = talkers[j];
                talkers[j] = tmp;
            }
        }
    }
    printf("\nTop talkers:\n");
    for (int i = 0; i < talker_count && i < 5; i++){
        struct in_addr a;
        a.s_addr = talkers[i].ip;
        printf(" %s: %d packets\n", inet_ntoa(a), talkers[i].count);
    }

    printf("TCP: %d UDP: %d ICMP: %d\n", tcp_count, udp_count, icmp_count);
    printf("Total packets: %d\n", total_count);
    printf("\nShutting down. Bye untill next time.\n");
    return 0;
} 
