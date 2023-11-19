#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#define BUF_SIZE 128
int fd, errcode;
ssize_t n;
socklen_t addrlen;
struct addrinfo hints, *res;
struct sockaddr_in addr;
char buffer[BUF_SIZE];
char msg[BUF_SIZE];

void parse_msg(char *buffer, char *msg) {
    char *temp;

    // command
    temp = strtok(buffer, " ");
    if (!strcmp(temp, "login")) {
        strcat(msg, "LIN");
    }
    while (temp != NULL) {
        temp = strtok(NULL, " ");
        if (temp != NULL) {
            strcat(msg, " ");
            strcat(msg, temp);
        }
    };
    strcat(msg, "\n");
}

int main(int argc, char **argv) {
    // UDP socket
    fd = socket(AF_INET, SOCK_DGRAM, 0);

    if (fd == -1) /*error*/
        exit(1);
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    // IPv4
    // UDP socket
    errcode = getaddrinfo("193.136.138.142", "58001", &hints, &res);
    if (errcode != 0) /*error*/
        exit(1);

    while (1) {
        // read message from terminal
        fgets(buffer, BUF_SIZE, stdin);
        int str_len = strlen(buffer);
        memset(msg, 0, BUF_SIZE);
        parse_msg(buffer, msg);
        printf("%s\n", msg);

        n = sendto(fd, msg, str_len, 0, res->ai_addr, res->ai_addrlen);
        if (n == -1) /*error*/
            exit(1);
        addrlen = sizeof(addr);

        memset(buffer, 0, BUF_SIZE);
        n = recvfrom(fd, buffer, BUF_SIZE, 0, (struct sockaddr *)&addr,
                     &addrlen);
        if (n == -1) /*error*/
            exit(1);

        write(1, "echo: ", 6);
        write(1, buffer, n);
    }

    freeaddrinfo(res);
    close(fd);
}