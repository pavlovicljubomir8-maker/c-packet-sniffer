// cli.h
#ifndef CLI_H
#define CLI_H

struct sniffer_config {
    int filter;          
    char *pcap_filename;  
    int filter_port;      
    char *filter_host;    
};

// Returns 0 to continue, 1 to exit(0) (e.g. --help), 2 to exit(1) (bad args).
int parse_args(int argc, char *argv[], struct sniffer_config *cfg);

#endif
