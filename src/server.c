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
#define BUF_SIZE 128
#define MAX_USERS 100
#define LOGOUT 0
#define UNREGISTER 1

int fd_udp, fd_tcp;
ssize_t n;
socklen_t addrlen;
struct addrinfo hints_udp, hints_tcp, *res_udp, *res_tcp;
struct sockaddr_in addr;
char buffer[BUF_SIZE];
char msg[BUF_SIZE];

struct User {
    int UID;
    char password[9];  // 8 characters + null terminator
};

struct User registered_users[MAX_USERS];  // Array to store user data
struct User logged_users[MAX_USERS];  // Array to store user data
int RegisteredNumUsers = 0;  // Number of users currently registered
int LoggedNumUsers = 0;  // Number of users currently logged in

void LoginUser(int userID, const char *password) {
    if (LoggedNumUsers < MAX_USERS) {
        logged_users[LoggedNumUsers].UID = userID;
        strcpy(logged_users[LoggedNumUsers].password, password);
        LoggedNumUsers++;
        printf("User logged in successfully.\n");
    } else {
        printf("Cannot add more users. Maximum limit reached.\n");
    }
}


void LogoutUser(int pos) {
    
    // Move the last user to the position of the removed user
    logged_users[pos] = logged_users[LoggedNumUsers - 1];
    logged_users[LoggedNumUsers - 1].UID = 0;
    strcpy(logged_users[LoggedNumUsers - 1].password,"");
    LoggedNumUsers--;
}

void RegisterUser(int userID, const char *password) {
    if (RegisteredNumUsers < MAX_USERS) {
        registered_users[RegisteredNumUsers].UID = userID;
        strcpy(registered_users[RegisteredNumUsers].password, password);
        RegisteredNumUsers++;
        LoginUser(userID,password);
        printf("User registered successfully.\n");
    } else {
        printf("Cannot register more users. Maximum limit reached.\n");
    }
}

void UnregisterUser(int pos) {
    
    // Move the last user to the position of the removed user
    registered_users[pos] = registered_users[RegisteredNumUsers - 1];
    registered_users[RegisteredNumUsers - 1].UID = 0;
    strcpy(registered_users[RegisteredNumUsers - 1].password,"");
    RegisteredNumUsers--;
}

/*
void LogoutUser(int userID) {
    int i, registered = 0;

    for (i = 0; i < RegisteredNumUsers; i++) {
        if (registered_users[i].UID == userID) {
            registered = 1;
            break;
        }
    }

    if (registered) {
        // Move the last user to the position of the removed user
        registered_users[i] = registered_users[RegisteredNumUsers - 1];
        RegisteredNumUsers--;
        registered_users[RegisteredNumUsers - 1].UID = 0;
        strcpy(registered_users[RegisteredNumUsers - 1].password,"");
        printf("User with ID %d removed successfully.\n", userID);
    } else {
        printf("User with ID %d not found.\n", userID);
    }
}

*/

/* Funções de comandos */
int login_user(int uid, char *password,char *msg) {
    for (int i = 0; i < RegisteredNumUsers; i++) {
        if (registered_users[i].UID == uid) {
            if (strcmp(registered_users[i].password,password) == 0) {
                sprintf(msg, "RLI OK\n");
                LoginUser(uid,password);
                return 0;
            }
            else sprintf(msg, "RLI NOK\n");
            return 0;
        }
    }
    RegisterUser(uid,password);
    sprintf(msg, "RLI REG\n");
    return 0;
}
int unregister_logout_user(int uid,char *msg,int type) {
    for (int i = 0; i < RegisteredNumUsers; i++) {
        if (registered_users[i].UID == uid) {
            for (int j = 0; j < LoggedNumUsers; j++) {
                if (logged_users[j].UID == uid) {
                    if (type==LOGOUT) {
                        sprintf(msg, "RLO OK\n");
                        LogoutUser(j);
                        return 0;  
                    }
                    else {
                        sprintf(msg, "RUR OK\n");
                        LogoutUser(j);
                        UnregisterUser(i);
                        return 0;  
                    }  
                }
            }
            if (type==LOGOUT) {
                sprintf(msg, "RLO NOK\n");
                return 0;
            }
            else {
                sprintf(msg, "RUR NOK\n");
                return 0;
            }  
        }
    }
    if (type==LOGOUT) {
        sprintf(msg, "RLO UNR\n");
    }
    else {
        sprintf(msg, "RUR UNR\n");
    }
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
    int uid;
    char password[9];
    /* Lê da socket (fd_udp) 128 bytes e guarda-os no buffer.
    Existem flags opcionais que não são passadas (0).
    O endereço do cliente (e o seu tamanho) são guardados para mais tarde
    devolver o texto */
    n = recvfrom(fd_udp, buffer, 128, 0, (struct sockaddr *)&addr, &addrlen);
    if (n == -1) return -1;

    // TODO: INTERPRETAR MENSAGENS DO CLIENTE
    sscanf(buffer, "%s ", temp);
    if (!strcmp(temp, "LIN")) {
        // login
        if (sscanf(buffer, "LIN %d %s", &uid, password) == 2)
            login_user(uid, password,msg);
    } 
    else if (!strcmp(temp, "LOU")) {
        // logout
        if (sscanf(buffer, "LOU %d %s", &uid, password) == 2)
            unregister_logout_user(uid, msg,LOGOUT);
    }

    else if (!strcmp(temp, "UNR")) {
        // logout
        if (sscanf(buffer, "UNR %d %s", &uid, password) == 2)
            unregister_logout_user(uid, msg,UNREGISTER);
    }

     /* Faz 'echo' da mensagem recebida para o STDOUT do servidor 
        printf("UDP | Received message | %d bytes | %s\n", n, buffer);
     */
     


    /* Envia a mensagem recebida (atualmente presente no buffer) para o
     * endereço 'addr' de onde foram recebidos dados */
    n = sendto(fd_udp, msg, strlen(msg) + 1, 0, (struct sockaddr *)&addr, addrlen);
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
    printf("TCP | fd:%d\t| Received %zd bytes | %s\n", fd, n, buffer);
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
        printf("REINICIA MSG\n");
        memset(msg, 0, BUF_SIZE);
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