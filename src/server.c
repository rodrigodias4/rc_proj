#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <time.h>

#define DEBUG 1
#define PORT "58051"
#define BUF_SIZE 128
#define PASSWORD_SIZE 9

int fd_udp, fd_tcp;
ssize_t n;
socklen_t addrlen;
struct addrinfo hints_udp, hints_tcp, *res_udp, *res_tcp;
struct sockaddr_in addr;
char buffer[BUF_SIZE];
char msg[1024];
char proj_path[BUF_SIZE] = "";  // change this
int current_aid = 100;
time_t fulltime;
char time_str[20];

long get_file_size(char *filename) {
    struct stat file_status;
    if (stat(filename, &file_status) < 0) {
        return -1;
    }

    return file_status.st_size;
}

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

int Create_Initial_Dirs() {
    int ret;
    ret = mkdir("USERS", 0700);
    if (ret == -1) return -1;
    ret = mkdir("AUCTIONS", 0700);
    if (ret == -1) {
        return -1;
    }
    return 0;
}

int create_file(char *path, char *content) {
    // argument content = "" (empty file)
    FILE *fp;
    fp = fopen(path, "w");
    if (fp == NULL) {
        return -1;
    }
    if (strcmp(content, "") != 0) {
        fprintf(fp, "%s", content);
    }
    fclose(fp);
    return 0;
}
int is_Directory_Exists(const char *path) {
    // full path as argument
    DIR *dir = opendir(path);
    if (dir) {
        /* Directory exists. */
        closedir(dir);
        return 1;
    } else if (ENOENT == errno) {
        /* Directory does not exist. */
        return 0;
    } else {
        /* opendir() failed for some other reason. */
        return -1;
    }
}

int is_File_Exists(const char *filename) {
    // relative path as argument
    if (access(filename, F_OK) != -1) {
        return 1;
    }
    return 0;
}

void get_current_time() {
    struct tm *current_time;
    time(&fulltime);
    current_time = gmtime(&fulltime);
    sprintf(time_str,"%4d-%02d-%02d %02d:%02d:%02d",
    current_time->tm_year + 1900, current_time->tm_mon+1, current_time->tm_mday ,
    current_time->tm_hour,current_time->tm_min,current_time->tm_sec) ;
}


int is_logged_in(int uid) {
    int file_exists;
    char login_path[BUF_SIZE];
    sprintf(login_path, "USERS/%d/%d_login.txt", uid, uid);
    file_exists = is_File_Exists(login_path);
    if (file_exists == -1) {
        return -1;
    }

    return file_exists;
}

int add_auction_to_auctions(int uid,int timeactive,char *fname,char *aname,float start_value) {
    char auction_dir[BUF_SIZE], asset_dir[BUF_SIZE], bids_dir[BUF_SIZE], start_path[BUF_SIZE] ,content[BUF_SIZE];
    int ret;
    sprintf(auction_dir, "AUCTIONS/%03d", current_aid);
    ret = mkdir(auction_dir, 0700);
    if (ret == -1) return -1;

    sprintf(asset_dir, "AUCTIONS/%03d/ASSET", current_aid);
    ret = mkdir(asset_dir, 0700);
    if (ret == -1) return -1;

    sprintf(bids_dir, "AUCTIONS/%03d/BIDS", current_aid);
    ret = mkdir(bids_dir, 0700);
    if (ret == -1) return -1;

    get_current_time();

    sprintf(start_path, "AUCTIONS/%d/START_%d.txt", current_aid,current_aid);

    //UID name asset fname start value timeactive start datetime start fulltime
    sprintf(content,"%d %s %s %f %d %s %ld",uid,aname,fname,start_value,timeactive,time_str,fulltime);

    ret = create_file(start_path,content);
    if (ret == -1) return -1;

    return 0;
}

int Login_User(int uid, char *password) {
    int dir_exists;
    char uid_path[BUF_SIZE];
    char login_path[BUF_SIZE];
    char pass_path[BUF_SIZE];
    sprintf(uid_path, "%s/USERS/%d", proj_path, uid);
    sprintf(pass_path, "USERS/%d/%d_pass.txt", uid, uid);
    sprintf(login_path, "USERS/%d/%d_login.txt", uid, uid);
    dir_exists = is_Directory_Exists(uid_path);
    int txt1;
    int txt2;
    if (dir_exists == -1) {
        return -1;
    }
    if (dir_exists) {
        int file_exists = is_File_Exists(pass_path);
        if (file_exists == -1) {
            return -1;
        }

        if (file_exists) {
            // User is registered
            FILE *fp = fopen(pass_path, "r");
            if (fp == NULL) {
                return -1;
            }
            char file_password[BUF_SIZE];
            fgets(file_password, BUF_SIZE, fp);
            if (strcmp(password, file_password) == 0) {
                // User logged in correctly
                txt1 = create_file(login_path, "");
                if (txt1 == -1) return -1;
                sprintf(msg, "RLI OK\n");
            } else {
                // User not logged in correctly
                sprintf(msg, "RLI NOK\n");
            }
        }

        else {
            // User was unregistered
            txt1 = create_file(pass_path, password);
            if (txt1 == -1) return -1;

            txt2 = create_file(login_path, "");
            if (txt2 == -1) return -1;
            sprintf(msg, "RLI REG\n");
        }
    } else {
        // Never registered before
        int ret;
        char hosted_path[BUF_SIZE];
        char bidded_path[BUF_SIZE];
        sprintf(uid_path, "USERS/%06d", uid);
        sprintf(hosted_path, "USERS/%06d/HOSTED", uid);
        sprintf(bidded_path, "USERS/%06d/BIDDED", uid);

        ret = mkdir(uid_path, 0700);
        if (ret == -1) return -1;

        ret = mkdir(hosted_path, 0700);
        if (ret == -1) return -1;

        ret = mkdir(bidded_path, 0700);
        if (ret == -1) return -1;

        txt1 = create_file(pass_path, password);
        if (txt1 == -1) return -1;

        txt2 = create_file(login_path, "");
        if (txt2 == -1) return -1;

        sprintf(msg, "RLI REG\n");
    }
    return 0;
}

int Logout_User(int uid) {
    int dir_exists;
    char uid_path[BUF_SIZE];
    char login_path[BUF_SIZE];
    char pass_path[BUF_SIZE];
    sprintf(uid_path, "%s/USERS/%d", proj_path, uid);
    sprintf(pass_path, "USERS/%d/%d_pass.txt", uid, uid);
    sprintf(login_path, "USERS/%d/%d_login.txt", uid, uid);
    dir_exists = is_Directory_Exists(uid_path);
    if (dir_exists == -1) {
        return -1;
    }
    if (dir_exists) {
        int file_exists = is_File_Exists(pass_path);
        if (file_exists == -1) {
            return -1;
        }

        if (file_exists) {
            // User is registered
            file_exists = is_File_Exists(login_path);
            if (file_exists == -1) {
                return -1;
            }
            if (file_exists) {
                // User is logged in (do the Logout)
                unlink(login_path);
                sprintf(msg, "RLO OK\n");
            } else {
                // User is not logged in
                sprintf(msg, "RLO NOK\n");
            }
        } else {
            // User was unregistered
            sprintf(msg, "RLO UNR\n");
        }
    } else {
        // User was never registered
        sprintf(msg, "RLO UNR\n");
    }
    return 0;
}

int Unregister_User(int uid) {
    int dir_exists;
    char uid_path[BUF_SIZE];
    char login_path[BUF_SIZE];
    char pass_path[BUF_SIZE];
    sprintf(uid_path, "%s/USERS/%d", proj_path, uid);
    sprintf(pass_path, "USERS/%d/%d_pass.txt", uid, uid);
    sprintf(login_path, "USERS/%d/%d_login.txt", uid, uid);
    dir_exists = is_Directory_Exists(uid_path);
    if (dir_exists == -1) {
        return -1;
    }
    if (dir_exists) {
        int file_exists = is_File_Exists(pass_path);
        if (file_exists == -1) {
            return -1;
        }

        if (file_exists) {
            // User is registered
            file_exists = is_File_Exists(login_path);
            if (file_exists == -1) {
                return -1;
            }
            if (file_exists) {
                // User is logged in (do the Unregister)
                unlink(login_path);
                unlink(pass_path);
                sprintf(msg, "RUR OK\n");
            } else {
                // User is not logged in
                sprintf(msg, "RUR NOK\n");
            }
        } else {
            // User was unregistered
            sprintf(msg, "RUR UNR\n");
        }
    } else {
        // User was never registered
        sprintf(msg, "RUR UNR\n");
    }
    return 0;
}

/* Funções de comandos */
int login_user(int uid, char *password) {
    if (Login_User(uid, password) != -1) {
        
        return 0;
    } else {
        // define server error TODO
        return -1;
    }
}
int logout_user(int uid) {
    if (Logout_User(uid) != -1) {
        return 0;
    } else {
        // define server error TODO
        return -1;
    }
    return 0;
}

int unregister_user(int uid) {
    if (Unregister_User(uid) != -1) {
        return 0;
    } else {
        // define server error TODO
        return -1;
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
    char temp[BUF_SIZE];
    int uid;
    char password[9];
    /* Lê da socket (fd_udp) BUF_SIZE bytes e guarda-os no buffer.
    Existem flags opcionais que não são passadas (0).
    O endereço do cliente (e o seu tamanho) são guardados para mais tarde
    devolver o texto */
    n = recvfrom(fd_udp, buffer, BUF_SIZE, 0, (struct sockaddr *)&addr,
                 &addrlen);
    if (n == -1) return -1;

    if (DEBUG) printf("UDP | Received %zd bytes | %s\n", n, buffer);
    // TODO: INTERPRETAR MENSAGENS DO CLIENTE
    sscanf(buffer, "%s ", temp);
    if (!strcmp(temp, "LIN")) {
        // login
        if (sscanf(buffer, "LIN %d %s", &uid, password) == 2 && input_verified(uid,password)) { //error
            login_user(uid, password);
        }
        else {
            return -1;
        }
    } 
    else if (!strcmp(temp, "LOU")) {
        // logout
        if (sscanf(buffer, "LOU %d %s", &uid, password) == 2 && input_verified(uid,password)) {
            logout_user(uid);
        }
        else {
            return -1;
        }
    }

    else if (!strcmp(temp, "UNR")) {
        // unregister
        if (sscanf(buffer, "UNR %d %s", &uid, password) == 2 && input_verified(uid,password)) {
            unregister_user(uid);
        }
        else {
            return -1;
        }
    }

    // implement the other udp commands 

    printf("SERVER MSG: %s", msg);
    n = sendto(fd_udp, msg, strlen(msg), 0, (struct sockaddr *)&addr,   // strlen(msg) + 1 changed to strlen(msg)
               addrlen);

    if (n == -1) return -1;
    return 0;
}

int download_file(int fd, char *fname, int fsize) {
    char downloaded[BUF_SIZE];
    strcpy(fname, "test2.txt");
    int new_file = open(fname, O_WRONLY | O_APPEND | O_CREAT, 0777);
    printf("Created file %s, writing...\n", fname);
    while (fsize > 0) {
        n = read(fd, downloaded, 128);
        if (n == -1) {
            if (DEBUG)
                printf("TCP | Error downloading file (connected) %d\n", fd);
            return -1;
        }
        n = write(new_file, downloaded, 128);
        if (n == -1) {
            if (DEBUG)
                printf("TCP | Error writing downloaded file (connected) %d\n",
                       fd);
            return -1;
        }
        /* printf("Wrote %zd bytes\n",n); */
        fsize -= n;
    }
    close(new_file);
    printf("Finished writing file %s (%ld bytes)\n", fname,
           get_file_size(fname));
    return 0;
}

int tcp_opa(int fd, char *return_msg) {
    char fname[BUF_SIZE], aname[BUF_SIZE], password[BUF_SIZE],users_hosted_path[BUF_SIZE];
    int uid, timeactive, fsize, res;
    float start_value;
    if (sscanf(buffer, "OPA %d %s %s %f %d %s %d", &uid, password, aname,
               &start_value, &timeactive, fname, &fsize) != 7)
        return -1;
    if (!is_logged_in(uid)) {
        sprintf(return_msg, "ROA NLG\n");
        return 0;
    }
    /* TODO: create auction files
    if (download_file(fd, fname, fsize) == -1) return -1; */

    res = add_auction_to_auctions(uid,timeactive,fname,aname,start_value);
    if (res==-1) {
        return -1;
    }

    sprintf(users_hosted_path, "USERS/%06d/HOSTED/%d.txt", uid,current_aid);
    res = create_file(users_hosted_path,"");;
    if (res==-1) {
        return -1;
    }

    sprintf(return_msg, "ROA OK\n");

    current_aid++;
    return 0;
}

int auction_exists(int aid) {
    // TODO
    return 1;
}

int auction_owned_by(int aid, int uid) {
    // TODO
    return 1;
}

int auction_ended(int aid) {
    // TODO
    return 1;
}

int tcp_cls(char *return_msg) {
    printf("CHEGAS1/n");
    time_t start_time=0,duration_time=0;
    FILE *fp;
    int uid,timeactive=0,t1,t2,ret,aid;
    float start_value=0;
    char password[PASSWORD_SIZE], path[BUF_SIZE],file_content[BUF_SIZE],
    fname[BUF_SIZE],aname[BUF_SIZE],start_time_string[20];
    if (sscanf(buffer, "CLS %d %s %d", &uid, password, &aid) != 3) return -1;
    if (!is_logged_in(uid)) {
        sprintf(return_msg, "RCL NLG\n");
    } else if (!auction_exists(aid)) {
        sprintf(return_msg, "RCL EAU\n");
    } else if (!auction_owned_by(aid, uid)) {
        sprintf(return_msg, "RCL EOW\n");
    } else if (!auction_ended(aid)) {
        sprintf(return_msg, "RCL END\n");
    } else {
        sprintf(return_msg, "RCL OK\n");
    }
    printf("CHEGAS2/n");
    sprintf(path,"AUCTIONS/%d/START_%d.txt", aid,aid);
    fp = fopen(path, "r");
    if (fp == NULL) {
        return -1;
    }
    fgets(file_content, BUF_SIZE, fp);
    sscanf(file_content,"%d %s %s %f %d %s %ld",uid,aname,fname,start_value,timeactive,start_time_string,start_time);
    get_current_time();
    duration_time = fulltime - start_time;
    sprintf(file_content, "%s %ld",time_str,duration_time);
    sprintf(path,"AUCTIONS/%d/END_%d.txt", aid,aid);
    ret = create_file(path,file_content);
    if (ret==-1) {
        return -1;
    }
    return 0;
}

int tcp_sas(int fd, char *return_msg) {
    int aid, fsize = 0;
    char fbuf[1024] = "", fname[128] = "*file name*", fpath[128] = "";
    if (sscanf(buffer, "SAS %d", &aid) != 1) return -1;
    if (!auction_exists(aid)) return -1;
    sprintf(fpath, "AUCTIONS/%d/%s", aid, fname);
    if (!is_File_Exists(fpath)) return -1;

    sprintf(return_msg, "RSA OK %s %d\n", fname, fsize);
    n = write(fd, return_msg, strlen(return_msg) + 1);
    if (n == -1) {
        if (DEBUG) printf("TCP | Error writing in socket (connected) %d\n", fd);
        return -1;
    }

    // TODO: SEND FILE

    return 0;
}

int place_bid(int aid, float value) {
    // TODO
    return 0;
}

int tcp_bid(char *return_msg) {
    char password[PASSWORD_SIZE];
    int uid, aid, success;
    float value;
    if (sscanf(buffer, "BID %d %s %d %f", &uid, password, &aid, &value) != 4)
        return -1;
    if (!is_logged_in(uid)) {
        sprintf(return_msg, "RBD NLG\n");
    } else if (!auction_exists(aid) || auction_ended(aid) ||
               (success = place_bid(aid, value)) == -1) {
        sprintf(return_msg, "RBD NOK\n");
    } else if (auction_owned_by(aid, uid)) {
        sprintf(return_msg, "RBD ILG\n");
    } else if (success == 0) {  // bid inferior
        sprintf(return_msg, "RBD REF\n");
    }
    return 0;
}

int handle_tcp(int fd) {
    char temp[BUF_SIZE];
    char return_msg[BUF_SIZE] = "";
    /* Já conectado, o cliente então escreve algo para a sua socket.
    Esses dados são lidos para o buffer. */
    n = read(fd, buffer, BUF_SIZE);
    if (n == -1) {
        if (DEBUG) printf("TCP | Error reading socket (connected) %d\n", fd);
        return -1;
    }

    /* Faz 'echo' da mensagem recebida para o STDOUT do servidor */
    printf("TCP | fd:%d\t| Received %zd bytes | %s\n", fd, n, buffer);
    sscanf(buffer, "%s ", temp);
    if (!strcmp(temp, "OPA")) {
        if (tcp_opa(fd, return_msg) == -1) {
            sprintf(return_msg, "ROA NOK\n");
        }
    } else if (!strcmp(temp, "CLS")) {
        if (tcp_cls(return_msg) == -1) sprintf(return_msg, "RCL NOK\n");
    } else if (!strcmp(temp, "SAS")) {
        if (tcp_sas(fd, return_msg) == -1)
            sprintf(return_msg, "RSA NOK\n");
        else
            return 0;
    } else if (!strcmp(temp, "BID")) {
        tcp_bid(return_msg);
    }

    /* Envia a mensagem recebida (atualmente presente no buffer) para a
     * socket */
    n = write(fd, return_msg, strlen(return_msg) + 1);
    if (n == -1) {
        if (DEBUG) printf("TCP | Error writing in socket (connected) %d\n", fd);
        return -1;
    }

    return n;
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
    getcwd(proj_path, 1024);

    Create_Initial_Dirs();
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
        memset(msg, 0, BUF_SIZE);
        fds_ready = fds;

        // Debugging fd list
        /* printf("File descriptors: ");
        for (int k = 0; k < max_fd + 1; k++) {
            if (FD_ISSET(k, &fds_ready)) {
                printf("%d ", k);
            }
        }
        printf("\n"); */

        if (select(max_fd + 1, &fds_ready, NULL, NULL, NULL) < 0) return -1;
        for (int i = 0; i <= max_fd; i++) {
            if (FD_ISSET(i, &fds_ready)) {
                printf("Socket %d pronto para ler\n", i);
                if (i == fd_udp)  // socket do udp pronto a ler
                    handle_udp();
                else if (i == fd_tcp) {     // socket do tcp pronto a ler;
                    fd_new = accept_tcp();  // retorna socket novo (específico à
                                            // comunicação) depois de aceitar;
                    max_fd = fd_new;
                    printf("Socket %d aceite, handling...\n", fd_new);
                    handle_tcp(fd_new);
                    /* FD_SET(fd_new, &fds);  // adiciona ao set de FDs */
                    printf("Finished handling\n");
                    close(fd_new);
                } else {
                    /* int bytes_read = handle_tcp(i);
                    if (bytes_read <= 0) FD_CLR(fd_new, &fds); */
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