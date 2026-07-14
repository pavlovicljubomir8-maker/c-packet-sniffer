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

    while (running) {
        int bytes = recvfrom(sock, buffer, sizeof(buffer), 0, NULL, NULL);
        if (bytes < 0) {
            perror("recvfrom");
            break;
        }
        
        if (bytes < 14 + (int)sizeof(struct iphdr)) continue;
        
        struct iphdr *ip = (struct iphdr *)(buffer + 14);
        struct in_addr src, dst;
        src.s_addr = ip->saddr;
        dst.s_addr = ip->daddr;


        int ip_header_len = ip-> ihl *4;

        if (bytes < 14 +ip_header_len + (int)sizeof(struct tcphdr)) continue;

        if (ip->protocol == 6){
            if(bytes < 14 + ip_header_len + (int)sizeof(struct tcphdr)) continue;
            struct tcphdr *tcp = (struct tcphdr *)(buffer + 14 + ip_header_len);
             printf("TCP %s:%d -> ", inet_ntoa(src), ntohs(tcp->source));
             printf("%s:%d\n", inet_ntoa(dst), ntohs(tcp->dest));
        }
        else if (ip->protocol == 17){
            if (bytes < 14 + ip_header_len + (int)sizeof(struct udphdr)) continue;
            struct udphdr *udp = (struct udphdr *)(buffer + 14 + ip_header_len);
            printf("UDP %s:%d -> ", inet_ntoa(src), ntohs(udp->source));
            printf("%s:%d\n", inet_ntoa(dst), ntohs(udp->dest));
        }
        else if( ip->protocol == 1) {
        printf("ICMP %s -> ", inet_ntoa(src));
        printf("%s\n", inet_ntoa(dst));
        }

    }
    close(sock);
    printf("\nShutting down. Bye untill next time.\n");
    return 0;
} 
