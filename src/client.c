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
#include <ctype.h>
#define DEBUG 1
#define BUF_SIZE 128
#define TCP_BUF_SIZE 1024
#define TRIM 1
#define NO_TRIM 0
#define PASSWORD_SIZE 9
int fd, errcode;
ssize_t n;
socklen_t addrlen;
struct addrinfo hints, *res;
struct sockaddr_in addr;
char asip[32] = "localhost";
char asport[8] = "58051";  // 58000 + group number (51)
// tejo ip: 193.136.138.142
// 58011 : server
// 58001 : echo
int uid = 0 , uid_test = 0;
char password[PASSWORD_SIZE] = "" , password_test[PASSWORD_SIZE] = "";

long get_file_size(char *filename) {
    struct stat file_status;
    if (stat(filename, &file_status) < 0) {
        return -1;
    }

    return file_status.st_size;
}

int valid_aid(int aid) { return (aid >= 100 && aid <= 999); }

/** Checks if the program has user UID and password (user has to login) */
int has_uid_pwd() { return uid != 0 && strcmp(password, "") != 0; }

int input_verified(int uid, char *password) {
    // Count the number of digits in the entered number
    int count_digits = 0;
    int temp = uid; // Temporary variable to store the number

    while (temp != 0) {
        temp /= 10;
        ++count_digits;
    }

    if(count_digits!=6 || strlen(password) != 8) {
        return 0;
    }

    while (*password) {
        if (!isalnum(*password)) {
            return 0; // Not alphanumeric
        }
        password++;
    }
    // All characters are alphanumeric

    return 1;
}

int handle_udp_server_msg(char* msg) {
    char temp[BUF_SIZE];
    char status[BUF_SIZE];
    sscanf(msg, "%s", temp);
    if (strcmp(temp,"RLI") == 0) {
        if (sscanf(msg, "RLI %s",status) == 1) {
            if (strcmp(status,"NOK")!=0) {
                uid = uid_test;
                strcpy(password,password_test);
            }
        }
        else {
            return -1;
        }
    }
    if (strcmp(temp,"RLO") == 0) {
        if (sscanf(msg, "RLO %s",status) == 1) {
            if (strcmp(status,"OK")==0) {
                uid = 0;
                strcpy(password,"");
            }
        }
        else {
            return -1;
        }
    }
    if (strcmp(temp,"RUR") == 0) {
        if (sscanf(msg, "RUR %s",status) == 1) {
            if (strcmp(status,"OK")==0) {
                uid = 0;
                strcpy(password,"");
            }
        }
        else {
            return -1;
        }
    }
    return 0;
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

    n = sendto(fd, msg, strlen(msg), 0, res->ai_addr, res->ai_addrlen);
    if (n == -1) /*error*/
        exit(1);
    addrlen = sizeof(addr);

    memset(buf_udp, 0, BUF_SIZE);
    n = recvfrom(fd, buf_udp, BUF_SIZE, 0, (struct sockaddr *)&addr, &addrlen);
    if (n == -1) /*error*/
        exit(1);

    write(1, "server_output: ", 16);
    write(1, buf_udp, n);

    handle_udp_server_msg(buf_udp);

    freeaddrinfo(res);
    close(fd);

    return 0;
}

/* TCP */

int tcp_open() {
    /* Cria um socket TCP (SOCK_STREAM) para IPv4 (AF_INET).
    É devolvido um descritor de ficheiro (fd) para onde se deve comunicar. */
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1) {
        if (DEBUG) printf("TCP | Error creating socket\n");
        return -1;
    }

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;  // TCP socket

    errcode = getaddrinfo(asip, asport, &hints, &res);
    if (errcode != 0) {
        if (DEBUG) printf("TCP | Error on getaddrinfo\n");
        return -1;
    }

    /* Em TCP é necessário estabelecer uma ligação com o servidor primeiro
       (Handshake). Então primeiro cria a conexão para o endereço obtido através
       de `getaddrinfo()`. */
    n = connect(fd, res->ai_addr, res->ai_addrlen);
    if (n == -1) {
        if (DEBUG) printf("TCP | Error on connect\n");
        return -1;
    }

    return 0;
}

int tcp_talk(char *msg, int trim) {
    /* char buf_tcp[TCP_BUF_SIZE]; */
    int str_len = strlen(msg);
    if (trim < 0 || trim > 1) return -1;
    /* Escreve a mensagem para o servidor, especificando o seu
     * tamanho */
    n = write(fd, msg, trim * (str_len) + (1 - trim) * TCP_BUF_SIZE);
    if (n == -1) {
        exit(1);
    }

    /* Lê 128 Bytes do servidor e guarda-os no buffer. */
    /* n = read(fd, buf_tcp, 128);
    if (n == -1) {
        exit(1);
    } */

    /* Imprime a mensagem "echo" e o conteúdo do buffer (ou seja, o que foi
    recebido do servidor) para o STDOUT (fd = 1) */
    /* printf("echo: %s\n", buf_tcp); */
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

int login(char *buffer, char *msg) {
    if (has_uid_pwd()) {
        printf("Try logging out first.\n");
        return -1;
    }
    if (sscanf(buffer, "login %d %s", &uid_test, password_test) != 2) return -1;
    if (!input_verified(uid_test, password_test)) return -1;
    sprintf(msg, "LIN %d %s", uid_test, password_test);

    return 0;
}

int logout(char *msg) {
    if (!has_uid_pwd()) {
        printf("UID and password not found locally. Try logging in first.\n");
        return -1;
    }
    sprintf(msg, "LOU %d %s", uid, password);

    return 0;
}

/* User input message interpretation */
int parse_msg_udp(char *buffer, char *msg) {
    char temp[BUF_SIZE];
    // command
    sscanf(buffer, "%s ", temp);
    if (!strcmp(temp, "login")) {
        if (login(buffer, msg) == -1) return -1;
    } else if (!strcmp(temp, "logout")) {
        if (logout(msg) == -1) return -1;
    } else if (!strcmp(temp, "unregister")) {
        if (!has_uid_pwd()) {
            printf(
                "UID and password not found locally. Try logging in first.\n");
            return -1;
        }
        sprintf(msg, "UNR %d %s", uid, password);
    } else if (!strcmp(temp, "myauctions") || !strcmp(temp, "ma")) {
        if (!has_uid_pwd()) {
            printf(
                "UID and password not found locally. Try logging in first.\n");
            return -1;
        }
        sprintf(msg, "LMA %d", uid);
    } else if (!strcmp(temp, "mybids") || !strcmp(temp, "mb")) {
        if (!has_uid_pwd()) {
            printf("UID and password not found locally. Try logging in first.\n");
            return -1;
        }
        sprintf(msg, "LMB %d", uid);
    } else if (!strcmp(temp, "list") || !strcmp(temp, "l")) {
        sprintf(msg, "LST");
    } else if (!strcmp(temp, "show_record") || !strcmp(temp, "sr")) {
        int aid;
        if (sscanf(buffer + strlen(temp) + 1, "%d", &aid) != 1) return -1;
        if (!valid_aid(aid)) {
            puts("show_record: invalid AID");
            return -1;
        }
        sprintf(msg, "SRC %d", aid);
    } else {
        return 0;  // input does not correspond to any of the above
    }

    return 1;  // return 1 if any correspond
}

int cls(char *buffer, char *msg) {
    int aid;
    if (sscanf(buffer, "close %d", &aid) != 1) return -1;
    if (!valid_aid(aid)) {
        puts("close: invalid AID");
        return -1;
    }
    sprintf(msg, "CLS %d %s %d\n", uid, password, aid);
    tcp(msg);

    return 0;
}

int opa(char *buffer, char *msg) {
    float start_value;
    int time_active, fsize, remaining;
    char description[BUF_SIZE], img_fname[BUF_SIZE];
    if (sscanf(buffer, "open %s %s %f %d", description, img_fname, &start_value,
               &time_active) != 4) {
        puts("open: Invalid arguments");
        return -1;
    }

    if (uid == 0 || !strlen(password)) {
        printf("open: Not logged in.\n");
        return -1;
    }

    fsize = get_file_size(img_fname);
    if (fsize < 0) return -1;

    sprintf(msg, "OPA %d %s %s %f %d %s %d\n", uid, password, description,
            start_value, time_active, img_fname, fsize);

    int file_to_send;
    if ((file_to_send = open(img_fname, O_RDONLY)) < 0) return -1;
    remaining = fsize;
    tcp_open();
    tcp_talk(msg, TRIM);  // send text before file
    while (remaining > 0) {
        if (DEBUG)
            printf("open: Sending file %s | %d bytes remaining \n", img_fname,
                   remaining);
        read(file_to_send, msg, BUF_SIZE);

        tcp_talk(msg, NO_TRIM);
        remaining -= BUF_SIZE;
    }
    tcp_talk(" \n", NO_TRIM);
    tcp_close();
    if (DEBUG) printf("Finished uploading file %s\n", img_fname);
    return 0;
}

int sas(char *buffer, char *msg, char *temp) {
    int aid;
    if (sscanf(buffer + strlen(temp) + 1, "%d", &aid) != 1) return -1;
    if (!valid_aid(aid)) {
        puts("show_asset: invalid AID");
        return -1;
    }
    sprintf(msg, "SAS %d\n", aid);
    tcp(msg);
    return 0;
}

int bid(char *buffer, char *msg) {
    float value;
    int aid;
    if (sscanf(buffer, "bid %d %f", &aid, &value) != 2) return -1;
    if (!valid_aid(aid)) return -1;

    sprintf(msg, "BID %d %s %d %f\n", uid, password, aid, value);
    tcp(msg);
    return 0;
}

/* NOT TESTED AT ALL */
int parse_msg_tcp(char *buffer, char *msg) {
    char temp[BUF_SIZE];

    sscanf(buffer, "%s ", temp);
    if (!strcmp(temp, "open")) {
        if (opa(buffer, msg) == 1) return -1;
    } else if (!strcmp(temp, "close")) {
        if (cls(buffer, msg) == -1) return -1;
        listener_RCL();
    } else if (!strcmp(temp, "show_asset") || !strcmp(temp, "sa")) {
        if (sas(buffer, msg, temp) == -1) return -1;
        listener_ROA();
    } else if (!strcmp(temp, "bid")) {
        if (bid(buffer, msg) == -1) return -1;
        // TODO
    } else {
        return 0;
    }
    if (DEBUG) printf("%s",msg);
    return 1;
}

int check_exit(char *buffer) {
    char temp[BUF_SIZE];
    sscanf(buffer, "%s", temp);
    if (!strcmp(temp, "exit")) {
        if (has_uid_pwd()) {
            printf("Try logging out first.\n");
            return -1;
        } else {
            return 1;
        }
    }

    return 0;
}

int parse_msg() {
    char buffer[BUF_SIZE], msg[1024];
    int res;
    if (fgets(buffer, BUFSIZ - 1, stdin) == NULL) return -1;
    res = check_exit(buffer);
    if (res == -1) return -1;  // error
    if (res == 1) {            // input corresponds to exit command
        return 1;
    }

    res = parse_msg_udp(buffer, msg);  // check udp commands
    if (res == -1) return -1;          // error
    if (res == 1) {                    // input corresponds to udp command
        strcat(msg, "\n");
        if (DEBUG) printf("Message sent -> %s", msg);
        udp(msg);
        return 0;
    }

    res = parse_msg_tcp(buffer, msg);  // check tcp commands
    if (res == -1) return -1;          // error
    if (res == 1) {                    // input corresponds to tcp command
        return 0;
    }

    return -1;  // input doesn't correspond to command
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
        if (DEBUG) printf("DEBUG: New while cycle\n");
        // read message from terminal
        int res;
        res = parse_msg();
        if (res == -1) {
            puts("Invalid input.");
        } else if (res == 1) {
            puts("Application terminated.");
            break;
        }
        fflush(stdout);
    }
}