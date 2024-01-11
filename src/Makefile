CC=gcc
CFLAGS=-W -Wall -Wextra -O3

all: server client

server: server.c
	$(CC) $(CFLAGS) server.c -o AS

client: client.c
	$(CC) $(CFLAGS) client.c -o User

clean:
	rm User AS
