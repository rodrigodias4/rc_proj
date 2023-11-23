#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define DEBUG 1
#define PORT "58051"

int fd_udp, fd_tcp;
ssize_t n;
socklen_t addrlen;
struct addrinfo hints_udp, hints_tcp, *res_udp, *res_tcp;
struct sockaddr_in addr;
char buffer[128];

/* Funções de comandos */
int login_user(char *uid, char *password) {
    // TODO
    printf("Logging in | UID: %s | Password %s\n", uid, password);
    return 0;
}
int logout_user(char *uid, char *password) {
    // TODO
    printf("Logging out | UID: %s | Password %s\n", uid, password);
    return 0;
}

int init_udp() {
    fd_udp = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd_udp == -1) {
        exit(1);
    }

    memset(&hints_udp, 0, sizeof hints_udp);
    hints_udp.ai_family = AF_INET;
    hints_udp.ai_socktype = SOCK_DGRAM;
    /* É passada uma flag para indicar que o socket é passivo.
    Esta flag é usada mais tarde pela função 'bind()' e indica que
    o socket aceita conexões. */
    hints_udp.ai_flags = AI_PASSIVE;

    /* Ao passar o endereço 'NULL', indicamos que somos nós o Host. */
    if (getaddrinfo(NULL, PORT, &hints_udp, &res_udp) != 0) exit(1);

    /* Quando uma socket é criada, não tem um endereço associado.
    Esta função serve para associar um endereço à socket, de forma a ser
    acessível por conexões externas ao programa. É associado o nosso endereço
    ('res_udp->ai_addr', definido na chamada à função 'getaddrinfo()').*/
    if (bind(fd_udp, res_udp->ai_addr, res_udp->ai_addrlen) == -1) exit(1);

    return 0;
}

int init_tcp() {
    fd_tcp = socket(AF_INET, SOCK_STREAM, 0);
    if (fd_tcp == -1) exit(1);

    memset(&hints_tcp, 0, sizeof hints_tcp);
    hints_tcp.ai_family = AF_INET;
    hints_tcp.ai_socktype = SOCK_STREAM;
    hints_tcp.ai_flags = AI_PASSIVE;

    if (getaddrinfo(NULL, PORT, &hints_tcp, &res_tcp) != 0) exit(1);

    if (bind(fd_tcp, res_tcp->ai_addr, res_tcp->ai_addrlen) == -1) exit(1);
    if (listen(fd_tcp, 10) < 0) exit(1);

    return 0;
}

int handle_udp() {
    int n;
    addrlen = sizeof(addr);
    char temp[128];
    char uid[32], password[32];
    /* Lê da socket (fd_udp) 128 bytes e guarda-os no buffer.
    Existem flags opcionais que não são passadas (0).
    O endereço do cliente (e o seu tamanho) são guardados para mais tarde
    devolver o texto */
    n = recvfrom(fd_udp, buffer, 128, 0, (struct sockaddr *)&addr, &addrlen);
    if (n == -1) return -1;

    // TODO: INTERPRETAR MENSAGENS DO CLIENTE
    sscanf(buffer, "%s ", temp);
    if (!strcmp(temp, "LIN")) {
        //login
        if (sscanf(buffer, "LIN %s %s",uid, password) == 2)
            login_user(uid, password);
    } else if (!strcmp(temp, "LOU")) {
        //login
        if (sscanf(buffer, "LOU %s %s",uid, password) == 2)
            logout_user(uid, password);
    }

    /* Faz 'echo' da mensagem recebida para o STDOUT do servidor */
    printf("UDP | Received message | %s\n", buffer);

    /* Envia a mensagem recebida (atualmente presente no buffer) para o
     * endereço 'addr' de onde foram recebidos dados */
    n = sendto(fd_udp, buffer, n, 0, (struct sockaddr *)&addr, addrlen);
    if (n == -1) return -1;
    return 0;
}

int handle_tcp(int fd) {
    char temp[128];
    /* Já conectado, o cliente então escreve algo para a sua socket.
    Esses dados são lidos para o buffer. */
    n = read(fd, buffer, 128);
    if (n == -1) {
        if (DEBUG) printf("TCP | Error reading socket (connected) %d\n", fd);
        return -1;
    }

    /* Faz 'echo' da mensagem recebida para o STDOUT do servidor */
    printf("TCP | fd:%d\t| Received %s\n", fd, buffer);
    sscanf(buffer, "%s ", temp);

    /* Envia a mensagem recebida (atualmente presente no buffer) para a
     * socket */
    n = write(fd, buffer, n);
    if (n == -1) {
        if (DEBUG) printf("TCP | Error writing in socket (connected) %d\n", fd);
        return -1;
    }

    return 0;
}

int accept_tcp() {
    int newfd;
    addrlen = sizeof(addr);

    /* Aceita uma nova conexão e cria uma nova socket para a mesma.
    Quando a conexão é aceite, é automaticamente criada uma nova socket
    para ela, guardada no 'newfd'.
    Do lado do cliente, esta conexão é feita através da função 'connect()'.
    */
    if ((newfd = accept(fd_tcp, (struct sockaddr *)&addr, &addrlen)) == -1) {
        if (DEBUG) printf("TCP | Error on accept\n");
        return -1;
    }

    if (DEBUG) printf("TCP | Accepted fd: %d\n", newfd);
    return newfd;
}

int main() {
    int fd_new, max_fd = 0;

    init_udp();
    init_tcp();

    fd_set fds, fds_ready;
    FD_ZERO(&fds);
    FD_SET(fd_udp, &fds);
    FD_SET(fd_tcp, &fds);
    max_fd = (fd_tcp > fd_udp) ? fd_tcp : fd_udp;

    /*     listen(fd_tcp, 1);
        fd_new = accept_tcp();
        handle_tcp(fd_new); */
    /* Loop para receber bytes e processá-los */
    while (1) {
        fds_ready = fds;
        if (select(max_fd + 1, &fds_ready, NULL, NULL, NULL) < 0) return -1;
        for (int i = 0; i <= max_fd; i++) {
            if (FD_ISSET(i, &fds_ready)) {
                printf("Socket %d pronto para ler\n", i);
                if (i == fd_udp)  // socket do udp pronto a ler
                    handle_udp();
                else if (i == fd_tcp) {     // socket do tcp pronto a ler;
                    fd_new = accept_tcp();  // retorna socket novo (específico à
                                            // comunicação) depois de aceitar;
                    handle_tcp(fd_new);
                    FD_SET(fd_new, &fds);  // adiciona ao set de FDs
                } else {
                    handle_tcp(i);
                    // TODO: quando remover do fd_set?
                }
            }
        }
    }

    freeaddrinfo(res_udp);
    freeaddrinfo(res_tcp);
    close(fd_udp);
    close(fd_tcp);
}