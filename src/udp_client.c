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
#define DEBUG 1
#define BUF_SIZE 128
#define TCP_BUF_SIZE 1024
#define TRIM 1
#define NO_TRIM 0
int fd, errcode;
ssize_t n;
socklen_t addrlen;
struct addrinfo hints, *res;
struct sockaddr_in addr;
char msg[1024];
char asip[32] = "localhost";
char asport[8] = "58051";  // 58000 + group number (51)
// tejo ip: 193.136.138.142
// 58011 : server
// 58001 : echo
char uid[BUF_SIZE] = "";
char password[BUF_SIZE] = "";
char aid[BUF_SIZE] = "";

/** Checks if the program has user UID and password (user has to login) */
int has_uid_pwd() { return strcmp(uid, "") && strcmp(password, ""); }

int parse_msg_udp(char *buffer, char *msg) {
    char temp[BUF_SIZE];

    // command
    sscanf(buffer, "%s ", temp);
    if (!strcmp(temp, "login")) {
        scanf("%s %s", uid, password);
        sprintf(msg, "LIN %s %s", uid, password);
    } else if (!strcmp(temp, "logout")) {
        if (!has_uid_pwd()) {
            printf(
                "UID and password not found locally. Try logging in first.\n");
            return -1;
        }
        sprintf(msg, "LOU %s %s", uid, password);
    } else if (!strcmp(temp, "unregister")) {
        sprintf(msg, "UNR %s %s", uid, password);
    } else if (!strcmp(temp, "myauctions") || !strcmp(temp, "ma")) {
        sprintf(msg, "LMA %s", uid);
    } else if (!strcmp(temp, "mybids") || !strcmp(temp, "mb")) {
        sprintf(msg, "LMB %s", uid);
    } else if (!strcmp(temp, "list") || !strcmp(temp, "l")) {
        sprintf(msg, "LST");
    } else if (!strcmp(temp, "show_record") || !strcmp(temp, "sr")) {
        scanf("%s", aid);
        sprintf(msg, "SRC %s", aid);
    } else {
        return 0;  // input does not correspond to any of the above
    }

    return 1;  // return 1 if any correspond
}

int parse_msg_tcp(char *buffer, char *msg) { return 0; }

int parse_msg(char *msg) {
    char buffer[BUF_SIZE];
    int res;
    if (fgets(buffer, BUFSIZ - 1, stdin) == NULL) return -1;

    res = parse_msg_udp(buffer, msg);  // check udp commands
    if (res == -1) return -1;          // error
    if (res == 1) {                    // input corresponds to udp command
        strcat(msg, "\n");
        return 0;
    }

    res = parse_msg_tcp(buffer, msg);  // check tcp commands
    if (res == -1) return -1;          // error
    if (res == 1) {                    // input corresponds to tcp command
        strcat(msg, "\n");
        return 0;
    }

    return -1;  // input doesn't correspond to command
}

int udp(char *msg) {
    char buf_udp[BUF_SIZE];
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

    memset(buf_udp, 0, BUF_SIZE);
    n = recvfrom(fd, buf_udp, BUF_SIZE, 0, (struct sockaddr *)&addr, &addrlen);
    if (n == -1) /*error*/
        exit(1);

    write(1, "echo: ", 6);
    write(1, buf_udp, n);

    freeaddrinfo(res);
    close(fd);

    return 0;
}

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
    char buf_tcp[TCP_BUF_SIZE];
    int str_len = strlen(msg);
    if (msg[str_len] != '\n') msg[str_len] = '\n';
    if (trim < 0 || trim > 1) return -1;
    /* Escreve a mensagem para o servidor, especificando o seu
     * tamanho */
    n = write(fd, msg, trim * (strlen(msg) + 1) + (1 - trim) * TCP_BUF_SIZE);
    if (n == -1) {
        exit(1);
    }

    /* Lê 128 Bytes do servidor e guarda-os no buffer. */
    n = read(fd, buf_tcp, 128);
    if (n == -1) {
        exit(1);
    }

    /* Imprime a mensagem "echo" e o conteúdo do buffer (ou seja, o que foi
    recebido do servidor) para o STDOUT (fd = 1) */
    write(1, "echo: ", 6);
    write(1, buf_tcp, n);

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
    if (tcp_talk(msg, TRIM) == -1) return -1;
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
        memset(msg, 0, BUF_SIZE);
        parse_msg(msg);
    }
}