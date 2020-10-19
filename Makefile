CC=gcc
CFLAGS= -Wextra -Werror

make:
	$(CC) $(CFLAGS) -o ipk-sniffer main.c -g -lpcap

clean:
	rm *.o ipk-sniffer