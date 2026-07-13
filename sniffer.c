#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>


int main (void) {

    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        perror("socket");
        return 1;
    }

    unsigned char buffer[65536];

    while (1) {
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

        printf("Protocol %d | from %s", ip->protocol, inet_ntoa(src));
        printf(" to %s\n", inet_ntoa(dst));


    }
    return 0;
} 
