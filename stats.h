// stats.h
#ifndef STATS_H
#define STATS_H
#include <stdint.h>
#include <time.h>

#define MAX_TALKERS 1000

struct ip_counter { uint32_t ip; int count; };
struct talker_table { struct ip_counter talkers[MAX_TALKERS]; int count; };

void record_talker(struct talker_table *table, uint32_t ip);
void print_top_talkers(struct talker_table *table);
void print_rate_if_new_second(time_t now, time_t *last_rate_print,
                               int *packets_this_second, long *bytes_this_second);
#endif
