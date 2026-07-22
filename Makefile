CC = gcc
CFLAGS = -Wall -Wextra -g
SRCS = main.c cli.c capture.c pcap_writer.c stats.c parse_dns.c parse_tls.c parse_http.c
OBJS = $(SRCS:.c=.o)
TARGET = sniffer

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: clean
