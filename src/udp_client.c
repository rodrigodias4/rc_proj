#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#define BUF_SIZE 128
#define MSG_SIZE 1024
int fd, errcode;
ssize_t n;
socklen_t addrlen;
struct addrinfo hints, *res;
struct sockaddr_in addr;
char buffer[BUF_SIZE];
char msg[1024];
char asip[32] = "localhost";
char asport[8] = "58051";  // 58000 + group number (51)
// tejo ip: 193.136.138.142
// 58011 : server
// 58001 : echo
char *uid;
char *password;

long get_file_size(char *filename) {
    struct stat file_status;
    if (stat(filename, &file_status) < 0) {
        return -1;
    }

    return file_status.st_size;
}

/* TCP */

int tcp_open() {
    /* Cria um socket TCP (SOCK_STREAM) para IPv4 (AF_INET).
    É devolvido um descritor de ficheiro (fd) para onde se deve comunicar. */
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1) {
        exit(1);
    }

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;  // TCP socket

    errcode = getaddrinfo(asip, asport, &hints, &res);
    if (errcode != 0) {
        exit(1);
    }

    /* Em TCP é necessário estabelecer uma ligação com o servidor primeiro
       (Handshake). Então primeiro cria a conexão para o endereço obtido através
       de `getaddrinfo()`. */
    n = connect(fd, res->ai_addr, res->ai_addrlen);
    if (n == -1) {
        exit(1);
    }

    return 0;
}

int tcp_talk(char *msg, int trim) {
    int str_len = strlen(msg);
    if (msg[str_len] != '\n') msg[str_len] = '\n';
    if (trim < 0 || trim > 1) return -1;
    /* Escreve a mensagem para o servidor, especificando o seu
     * tamanho */
    n = write(fd, msg, trim * (strlen(msg) + 1) + (1 - trim) * MSG_SIZE);
    if (n == -1) {
        exit(1);
    }

    /* Lê 128 Bytes do servidor e guarda-os no buffer. */
    n = read(fd, buffer, 128);
    if (n == -1) {
        exit(1);
    }

    /* Imprime a mensagem "echo" e o conteúdo do buffer (ou seja, o que foi
    recebido do servidor) para o STDOUT (fd = 1) */
    write(1, "echo: ", 6);
    write(1, buffer, n);

    return 0;
}

int tcp_close() {
    /* Desaloca a memória da estrutura `res` e fecha o socket */
    freeaddrinfo(res);
    close(fd);

    return 0;
}

int tcp(char *msg) {
    if (tcp_open() == -1) return -1;
    if (tcp_talk(msg, 1) == -1) return -1;
    if (tcp_close() == -1) return -1;
    return 0;
}

/* Response listeners/interpreters */

int listener_ROA() {
    // TODO
    return 0;
}

int listener_RCL() {
    // TODO
    return 0;
}

int listener_RAS() {
    // TODO
    return 0;
}

int listener_RBD() {
    // TODO
    return 0;
}

int parse_msg(char *buffer, char *msg) {
    char aid[32];
    char *temp;
    char buffer2[BUF_SIZE];
    strncpy(buffer2, buffer, BUF_SIZE);

    // command
    temp = strtok(buffer, " ");
    if (!strcmp(temp, "login")) {
        strcat(msg, "LIN");
        uid = strtok(NULL, " ");
        strcat(msg, " ");
        strcat(msg, uid);
        password = strtok(NULL, " ");
        strcat(msg, " ");
        strcat(msg, password);
    } else if (!strcmp(temp, "logout")) {
        strcat(msg, "LOU");
        strcat(msg, " ");
        strcat(msg, uid);
        strcat(msg, " ");
        strcat(msg, password);
    } else if (!strcmp(temp, "unregister")) {
        strcat(msg, "UNR");
        strcat(msg, " ");
        strcat(msg, uid);
        strcat(msg, " ");
        strcat(msg, password);
    } else if (!strcmp(temp, "myauctions") || !strcmp(temp, "ma")) {
        strcat(msg, "LMA");
        strcat(msg, " ");
        strcat(msg, uid);
    } else if (!strcmp(temp, "mybids") || !strcmp(temp, "mb")) {
        strcat(msg, "LMB");
        strcat(msg, " ");
        strcat(msg, uid);
    } else if (!strcmp(temp, "open")) {
        float start_value;
        int time_active, fsize, j, bytes_string, remaining;
        char description[BUF_SIZE], img_fname[BUF_SIZE];
        if (sscanf(buffer2, "open %s %s %f %d", description, img_fname,
                   &start_value, &time_active) != 4)
            return -1;

        if (!strlen(uid) || !strlen(password)) return -1;

        fsize = get_file_size(img_fname);
        if (fsize < 0) return -1;

        bytes_string = sprintf(msg, "OPA %s %f %d %s %d", description,
                               start_value, time_active, img_fname, fsize);
        msg[bytes_string] = ' ';  // remove '\0'

        int file_to_send;
        if ((file_to_send = open(img_fname, O_RDONLY)) < 0) return -1;
        remaining = fsize;
        tcp_open();
        tcp_talk(msg, 0);  // send text before file
        while (remaining > 0) {
            read(file_to_send, msg, BUF_SIZE);
            tcp_talk(msg, 0);
            remaining -= BUF_SIZE;
        }
        tcp_talk(" \n", 0);
        tcp_close();

    } else if (!strcmp(temp, "close")) {
        if (sscanf(buffer2, "close %s", aid) != 1) return -1;

        sprintf(msg, "CLS %s %s %s\n", uid, password, aid);
        tcp(msg);
        listener_RCL();
    } else if (!strcmp(temp, "show_asset") || !strcmp(temp, "sa")) {
        if (sscanf(buffer2 + strlen(temp + 1), "%s", aid) != 2) return -1;
        sprintf(msg, "SAS %s\n", aid);
        tcp(msg);
        listener_ROA();
    } else if (!strcmp(temp, "bid")) {
        // TODO
    }

    return 0;
}

int udp(char *msg) {
    // UDP socket
    fd = socket(AF_INET, SOCK_DGRAM, 0);

    if (fd == -1) /*error*/
        exit(1);
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    // IPv4
    // UDP socket
    errcode = getaddrinfo(asip, asport, &hints, &res);
    if (errcode != 0) /*error*/
        exit(1);

    n = sendto(fd, msg, strlen(msg) + 1, 0, res->ai_addr, res->ai_addrlen);
    if (n == -1) /*error*/
        exit(1);
    addrlen = sizeof(addr);

    memset(buffer, 0, BUF_SIZE);
    n = recvfrom(fd, buffer, BUF_SIZE, 0, (struct sockaddr *)&addr, &addrlen);
    if (n == -1) /*error*/
        exit(1);

    write(1, "echo: ", 6);
    write(1, buffer, n);

    freeaddrinfo(res);
    close(fd);

    return 0;
}

int main(int argc, char **argv) {
    if (argc > 1) {
        for (int i = 1; i < argc && i < 5; i += 2) {
            if (!strcmp(argv[i], "-n") && (argc > i + 1)) {
                strcpy(asip, argv[i + 1]);
            }
            if (!strcmp(argv[i], "-p") && (argc > i + 1)) {
                strcpy(asport, argv[i + 1]);
            }
        }
    }
    /* printf("ip: %s\n", asip);
    printf("port: %s\n", asport); */

    while (1) {
        // read message from terminal
        fgets(buffer, BUF_SIZE, stdin);
        memset(msg, 0, BUF_SIZE);
        parse_msg(buffer, msg);
        printf("%s\n", msg);

        udp(msg);
    }
}