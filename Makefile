CC = gcc
CFLAGS = -Wall -Wextra
TARGET = sniffer

$(TARGET): sniffer.c
	$(CC) $(CFLAGS) sniffer.c -o $(TARGET)

clean:
	rm -f $(TARGET)	
