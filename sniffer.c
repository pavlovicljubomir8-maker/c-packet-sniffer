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
volatile sig_atomic_t running = 1;

void handle_sigint(int sig) {
    (void)sig;
    running = 0;
}

int main (void) {

    signal(SIGINT, handle_sigint);
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

    while (running) {
        int bytes = recvfrom(sock, buffer, sizeof(buffer), 0, NULL, NULL);
        if (bytes < 0) {
            perror("recvfrom");
            break;
        }

        total_count ++; 
        
        if (bytes < 14 + (int)sizeof(struct iphdr)) continue;
        
        struct iphdr *ip = (struct iphdr *)(buffer + 14);
        struct in_addr src, dst;
        src.s_addr = ip->saddr;
        dst.s_addr = ip->daddr;


        int ip_header_len = ip-> ihl *4;

        if (ip->protocol == 6){
            if(bytes < 14 + ip_header_len + (int)sizeof(struct tcphdr)) continue;
            struct tcphdr *tcp = (struct tcphdr *)(buffer + 14 + ip_header_len);
             printf("TCP %s:%d -> ", inet_ntoa(src), ntohs(tcp->source));
             printf("%s:%d\n", inet_ntoa(dst), ntohs(tcp->dest));
             tcp_count ++;
        }
        else if (ip->protocol == 17){
            if (bytes < 14 + ip_header_len + (int)sizeof(struct udphdr)) continue;
            struct udphdr *udp = (struct udphdr *)(buffer + 14 + ip_header_len);
            printf("UDP %s:%d -> ", inet_ntoa(src), ntohs(udp->source));
            printf("%s:%d\n", inet_ntoa(dst), ntohs(udp->dest));
            udp_count ++;
        }
        else if( ip->protocol == 1) {
        printf("ICMP %s -> ", inet_ntoa(src));
        printf("%s\n", inet_ntoa(dst));
        icmp_count ++;
        }
    }
    close(sock);
    printf("TCP: %d UDP: %d ICMP: %d\n", tcp_count, udp_count, icmp_count);
    printf("Total packets: %d\n", total_count);
    printf("\nShutting down. Bye untill next time.\n");
    return 0;
} 
