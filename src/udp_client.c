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
char asip[32] = "localhost";
char asport[8] = "58051";  // 58000 + group number (51)
// tejo ip: 193.136.138.142
// 58011 : server
// 58001 : echo
char uid[BUF_SIZE];
char password[BUF_SIZE];
char aid[BUF_SIZE];

void parse_msg(char *msg) {
    char temp[BUF_SIZE];

    // command
    scanf("%s", temp);
    if (!strcmp(temp, "login")) {
        scanf("%s %s", uid, password);
        sprintf(msg, "LIN %s %s", uid, password);
    }
    
    else if (!strcmp(temp, "logout")) {
        sprintf(msg, "LOU %s %s", uid, password);
    }
    else if (!strcmp(temp, "unregister")) { 
        sprintf(msg, "UNR %s %s", uid, password);
    }
    else if (!strcmp(temp, "myauctions") || !strcmp(temp, "ma")) {
        sprintf(msg, "LMA %s", uid);
    }
    else if (!strcmp(temp, "mybids") || !strcmp(temp, "mb")) {
        sprintf(msg, "LMB %s", uid); 
    }
    else if (!strcmp(temp, "list") || !strcmp(temp, "l")) {
        sprintf(msg, "LST"); 
    }
    else if (!strcmp(temp, "show_record") || !strcmp(temp, "sr")) {
        scanf("%s", aid);
        sprintf(msg, "SRC %s", aid);    
    }
    
    strcat(msg, "\n");
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

    n = sendto(fd, msg, strlen(msg)+1, 0, res->ai_addr, res->ai_addrlen);
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
}

int tcp(char *msg) {
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

    /* Escreve a mensagem "Hello!\n" para o servidor, especificando o seu
     * tamanho */
    n = write(fd, msg, strlen(msg)+1);
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

    /* Desaloca a memória da estrutura `res` e fecha o socket */
    freeaddrinfo(res);
    close(fd);
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


    while (1) {
        // read message from terminal
        memset(msg, 0, BUF_SIZE);
        parse_msg(msg);

        udp(msg);
    }
}