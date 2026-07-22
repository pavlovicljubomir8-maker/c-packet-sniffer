// stats.c
#include <stdio.h>
#include <arpa/inet.h>
#include "stats.h"

// linear search: increment if seen, append if new. O(n), fine at this scale.
void record_talker(struct talker_table *table, uint32_t ip) {
    for (int i = 0; i < table->count; i++) {
        if (table->talkers[i].ip == ip) { table->talkers[i].count++; return; }
    }
    if (table->count < MAX_TALKERS) {
        table->talkers[table->count].ip = ip;
        table->talkers[table->count].count = 1;
        table->count++;
    }
}
// selection sort by count descending, runs once at shutdown so O(n²) doesn't matter.
void print_top_talkers(struct talker_table *table) {
    for (int i = 0; i < table->count; i++) {
        for (int j = i + 1; j < table->count; j++) {
            if (table->talkers[j].count > table->talkers[i].count) {
                struct ip_counter tmp = table->talkers[i];
                table->talkers[i] = table->talkers[j];
                table->talkers[j] = tmp;
            }
        }
    }
    printf("\nTop talkers:\n");
    for (int i = 0; i < table->count && i < 5; i++) {
        struct in_addr a;
        a.s_addr = table->talkers[i].ip;
        printf(" %s: %d packets\n", inet_ntoa(a), table->talkers[i].count);
    }
}

void print_rate_if_new_second(time_t now, time_t *last_rate_print,
                               int *packets_this_second, long *bytes_this_second) {
    if (now > *last_rate_print) {
        printf(">>> Rate: %d packets/sec, %ld bytes/sec\n", *packets_this_second, *bytes_this_second);
        *packets_this_second = 0;
        *bytes_this_second = 0;
        *last_rate_print = now;
    }
}
