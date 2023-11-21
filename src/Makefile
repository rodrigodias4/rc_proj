CC=gcc
CFLAGS=-W -Wall -Wextra

all: server client

server: server.c
	$(CC) $(CFLAGS) server.c -o server

client: udp_client.c
	$(CC) $(CFLAGS) udp_client.c -o client

clean:
	rm server client
