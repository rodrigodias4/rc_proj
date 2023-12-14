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
#include <time.h>
#include <unistd.h>

#define DEBUG 1
#define PORT "58051"
#define BUF_SIZE 128
#define A_DESC_MAX_LEN 10 + 1
#define A_START_VALUE_MAX_LEN 6
#define A_DURATION_MAX_LEN 5
#define PASSWORD_SIZE 9

int fd_udp, fd_tcp, next_aid = 0;
ssize_t n;
socklen_t addrlen;
struct addrinfo hints_udp, hints_tcp, *res_udp, *res_tcp;
struct sockaddr_in addr;
char buffer[BUF_SIZE];
char msg[1024];
char proj_path[128] = "";

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

long get_file_size(char *filename) {
    struct stat file_status;
    if (stat(filename, &file_status) < 0) {
        return -1;
    }

    return file_status.st_size;
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
    /* DIR *dir = opendir(path);
    if (dir != NULL) {
        closedir(dir);
        return 1;
    } else {
        return 0;
    } */
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

int Create_Initial_Dirs() {
    int ret;
    char path[256];
    sprintf(path, "%s/USERS", proj_path);
    if (!is_Directory_Exists(path)) {
        ret = mkdir("USERS", 0700);
        if (ret == -1) return -1;
    }
    sprintf(path, "%s/AUCTIONS", proj_path);
    if (!is_Directory_Exists(path)) {
        ret = mkdir("AUCTIONS", 0700);
        if (ret == -1) return -1;
    }
    return 0;
}

int remove_auction(int aid) {
    char a_dir[256];
    sprintf(a_dir, "%s/AUCTIONS/%03d/", proj_path, aid);
    DIR *theFolder = opendir(a_dir);
    struct dirent *next_file;
    char filepath[256];

    while ((next_file = readdir(theFolder)) != NULL) {
        if (!strcmp(next_file->d_name, ".") || !strcmp(next_file->d_name, ".."))
            continue;
        // build the path for each file in the folder
        sprintf(filepath, "%s/%s", a_dir, next_file->d_name);
        remove(filepath);
    }
    closedir(theFolder);
    rmdir(a_dir);
    return 0;
}

int is_File_Exists(const char *filename) {
    return (access(filename, F_OK) != -1);
}

int is_logged_in(int uid) {
    // TODO
    return 1;
}

int password_correct(int uid, char *password) {
    char path[128], temp[9];
    sprintf(path, "%s/USERS/%03d/%03d_pass.txt", proj_path, uid, uid);
    int start_fd;
    start_fd = open(path, O_RDONLY);
    read(start_fd, temp, 8);
    close(start_fd);
    return !strcmp(password, temp);
}

int Login_User(int uid, char *password) {
    int dir_exists;
    char uid_path[256];
    char login_path[256];
    char pass_path[256];
    sprintf(uid_path, "%s/USERS/%d", proj_path, uid);
    sprintf(pass_path, "USERS/%d/%d_pass.txt", uid, uid);
    sprintf(login_path, "USERS/%d/%d_login.txt", uid, uid);
    dir_exists = is_Directory_Exists(uid_path);
    int txt1;
    int txt2;
    if (dir_exists == -1) {
        if (DEBUG) printf("login: dir_exists == -1");
        fflush(stdout);
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
        sprintf(uid_path, "USERS/%d", uid);
        sprintf(hosted_path, "USERS/%d/HOSTED", uid);
        sprintf(bidded_path, "USERS/%d/BIDDED", uid);

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
    int n, uid;
    addrlen = sizeof(addr);
    char temp[BUF_SIZE];
    char password[32];
    /* Lê da socket (fd_udp) BUF_SIZE bytes e guarda-os no buffer.
    Existem flags opcionais que não são passadas (0).
    O endereço do cliente (e o seu tamanho) são guardados para mais tarde
    devolver o texto */
    n = recvfrom(fd_udp, buffer, BUF_SIZE, 0, (struct sockaddr *)&addr,
                 &addrlen);
    if (n == -1) return -1;

    if (DEBUG) printf("UDP | Received %d bytes | %s\n", n, buffer);
    // TODO: INTERPRETAR MENSAGENS DO CLIENTE
    sscanf(buffer, "%s ", temp);
    if (!strcmp(temp, "LIN")) {
        // login
        if (sscanf(buffer, "LIN %d %s", &uid, password) == 2 && input_verified(uid,password)) {
            login_user(uid, password);
        }
        else {
            return -1;
        }
    } else if (!strcmp(temp, "LOU")) {
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
    n = sendto(fd_udp, msg, strlen(msg) + 1, 0, (struct sockaddr *)&addr,
               addrlen);

    if (n == -1) return -1;
    return 0;
}

int download_file(int fd, char *fname, int fsize, int newline_index) {
    char downloaded[BUF_SIZE];
    strcpy(fname, "test2.txt");
    int new_file = open(fname, O_WRONLY | O_TRUNC | O_CREAT, 0777);
    printf("Created file %s, writing...\n", fname);
    /* write(fd, buffer + newline_index, BUF_SIZE - newline_index - 1); */
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
        // printf("Wrote %zd bytes\n", n);
        fsize -= n;
    }
    close(new_file);
    printf("Finished writing file %s (%ld bytes)\n", fname,
           get_file_size(fname));
    return 0;
}

int tcp_opa(int fd, char *return_msg) {
    char fname[128], aname[A_DESC_MAX_LEN], password[128], a_dir[256],
        temp[BUF_SIZE];
    int uid, timeactive, fsize, start_value;

    if (sscanf(buffer, "OPA %d %s %s %d %d %s %d", &uid, password, aname,
               &start_value, &timeactive, fname, &fsize) != 7)
        return -1;
    if (!password_correct(uid, password))  // TODO
        return 0;
    if (!is_logged_in(uid)) {
        sprintf(return_msg, "ROA NLG\n");
        return 0;
    }
    sprintf(a_dir, "%s/AUCTIONS/%03d", proj_path, next_aid);

    // Create auction AID directory
    mkdir(a_dir, 0700);
    if (DEBUG) puts("Created auction folder. ");

    /* int newline_index;
    for (newline_index = 0; newline_index < strlen(buffer); newline_index++) {
        if (buffer[newline_index] == '\n') {
            newline_index++;
            break;
        }
    } */
    // Download asset file
    // if (download_file(fd, fname, fsize, newline_index) == -1) return -1;
    // Create START file
    char file_path[256];
    sprintf(file_path, "%s/START_%03d.txt", a_dir, next_aid);

    int start_fd;
    if ((start_fd = open(file_path, O_WRONLY | O_CREAT, 0777)) == -1) {
        puts("ERROR: Could not create start file.");
        return -1;
    }
    if (DEBUG) puts("Created start file. ");

    // Write contents into start file
    char start_content[512], start_datetime[128];

    time_t time_now;
    struct tm *time_info;
    time(&time_now);
    time_info = localtime(&time_now);
    strftime(start_datetime, 128, "%Y-%m-%d %X", time_info);

    sprintf(start_content, "%d %s %s %d %d %s %ld\n", uid, aname, fname,
            start_value, timeactive, start_datetime, time_now);
    write(start_fd, start_content, strlen(start_content));
    close(start_fd);

    // Create BIDS folder
    sprintf(file_path, "%s/BIDS/", a_dir);
    mkdir(file_path, 0700);
    if (DEBUG) puts("Created bids folder.\n");

    // Update User Hosted
    sprintf(file_path,"USERS/%d/HOSTED/%03d.txt",uid,next_aid);
    create_file(file_path,"");

    sprintf(return_msg, "ROA OK\n");
    // write(fd, return_msg, 127);
    next_aid++;
    return 0;
}

int auction_exists(int aid) {
    char temp_path[128];
    sprintf(temp_path, "%s/AUCTIONS/%03d/START_%03d.txt", proj_path, aid, aid);
    return is_File_Exists(temp_path);
}

int auction_owned_by(int aid, int uid) {
    char path[128], temp[128];
    sprintf(path, "%s/AUCTIONS/%03d/START_%03d.txt", proj_path, aid, aid);
    int start_fd, auction_uid;
    start_fd = open(path, O_RDONLY);
    read(start_fd, temp, 128);
    sscanf(temp, "%d", &auction_uid);
    close(start_fd);
    return auction_uid == uid;
}

int auction_ended(int aid) {
    char temp_path[128];
    sprintf(temp_path, "%s/AUCTIONS/%03d/END_%03d.txt", proj_path, aid, aid);
    return is_File_Exists(temp_path);
}

int tcp_cls(char *return_msg) {
    char password[PASSWORD_SIZE], datetime[128], path[128], file_content[128];
    int uid, aid, start_fd, end_fd;
    if (sscanf(buffer, "CLS %d %s %d", &uid, password, &aid) != 3) return -1;
    if (!is_logged_in(uid)) {
        sprintf(return_msg, "RCL NLG\n");
    } else if (!auction_exists(aid)) {
        sprintf(return_msg, "RCL EAU\n");
    } else if (!auction_owned_by(aid, uid)) {
        sprintf(return_msg, "RCL EOW\n");
    } else if (auction_ended(aid)) {
        sprintf(return_msg, "RCL END\n");
    }

    if (strlen(return_msg) > 0) return 0;

    // Get current time
    time_t time_now;
    struct tm *time_info;
    time(&time_now);
    time_info = localtime(&time_now);
    strftime(datetime, 128, "%Y-%m-%d %X", time_info);

    // Get auction start time
    time_t time_start;
    sprintf(path, "%s/AUCTIONS/%03d/START_%03d.txt", proj_path, aid, aid);
    if ((start_fd = open(path, O_RDONLY)) == -1) return -1;
    read(start_fd, file_content, 128);
    sscanf(file_content, "%*d %*s %*s %*d %*d %*s %*s %ld", &time_start);
    close(start_fd);

    // Write file contents
    sprintf(path, "%s/AUCTIONS/%03d/END_%03d.txt", proj_path, aid, aid);
    if ((end_fd = open(path, O_WRONLY | O_CREAT, 0777)) == -1) return -1;
    sprintf(file_content, "%s %ld\n", datetime, time_now - time_start);
    write(end_fd, file_content, strlen(file_content));
    close(end_fd);

    sprintf(return_msg, "RCL OK\n");

    return 0;
}

int tcp_sas(int fd, char *return_msg) {
    int aid, fsize = 0;
    char fbuf[1024] = "", fname[128] = "*file name*", fpath[128] = "";
    if (sscanf(buffer, "SAS %d", &aid) != 1) return -1;
    if (!auction_exists(aid)) return -1;
    sprintf(fpath, "AUCTIONS/%03d/%s", aid, fname);
    if (!is_File_Exists(fpath)) return -1;

    sprintf(return_msg, "RSA OK %s %d\n", fname, fsize);
    /* n = write(fd, return_msg, strlen(return_msg) + 1);
    if (n == -1) {
        if (DEBUG) printf("TCP | Error writing in socket (connected) %d\n", fd);
        return -1;
    } */

    // TODO: SEND FILE

    return 0;
}

int tcp_bid(int fd, char *return_msg) {
    char password[PASSWORD_SIZE], path[256], bid_content[128], datetime[128],
        start_content[128];
    int uid, aid, success, value, highest_bid, start_fd;

    if (sscanf(buffer, "BID %d %s %d %d", &uid, password, &aid, &value) != 4) {
        if (DEBUG) puts("ERROR: bid sscanf");
        sprintf(return_msg, "RBD NOK\n");
        /* } else if (!password_correct(uid, password)) {
            if (DEBUG) puts("Password incorrect");
            sprintf(return_msg, "RBD NOK\n"); */
    } else if (!is_logged_in(uid)) {
        sprintf(return_msg, "RBD NLG\n");
    } else if (auction_owned_by(aid, uid)) {
        sprintf(return_msg, "RBD ILG\n");
    } else if (!auction_exists(aid) || auction_ended(aid)) {
        if (DEBUG)
            printf("ERROR: %d %d", auction_exists(aid), auction_ended(aid));
        sprintf(return_msg, "RBD NOK\n");
    }
    // Uma das condições acima foi encontrada
    if (strlen(return_msg) != 0) return 0;

    // Check if higher bid exists
    struct dirent **filelist;
    int n_entries;
    sprintf(path, "%s/AUCTIONS/%03d/BIDS/", proj_path, aid);
    n_entries = scandir(path, &filelist, 0, alphasort);
    if (n_entries <= 0) {
        sprintf(return_msg, "RBD NOK\n");
        return 0;
    }
    if (n_entries > 2) {
        sscanf(filelist[n_entries - 1]->d_name, "%06d.txt", &highest_bid);
        if (value <= highest_bid) {  // bid inferior
            sprintf(return_msg, "RLI REF\n");
            return 0;
        }
    }

    // Create file
    int bid_fd;
    sprintf(path, "%s/AUCTIONS/%03d/BIDS/%06d.txt", proj_path, aid, value);
    if ((bid_fd = open(path, O_WRONLY | O_CREAT, 0777)) == -1) {
        puts("ERROR: Could not create file.");
        sprintf(return_msg, "RBD NOK\n");
        return -1;
    }
    if (DEBUG) puts("Created bid file. ");

    // Get current time
    time_t time_now;
    struct tm *time_info;
    time(&time_now);
    time_info = localtime(&time_now);
    strftime(datetime, 128, "%Y-%m-%d %X", time_info);

    // Get auction start time
    time_t time_start;
    sprintf(path, "%s/AUCTIONS/%03d/START_%03d.txt", proj_path, aid, aid);
    if ((start_fd = open(path, O_RDONLY)) == -1) return -1;
    read(start_fd, start_content, 128);
    sscanf(start_content, "%*d %*s %*s %*d %*d %*s %*s %ld", &time_start);
    close(start_fd);

    // Write file contents
    sprintf(bid_content, "%d %d %s %ld\n", uid, value, datetime,
            time_now - time_start);
    write(bid_fd, bid_content, strlen(bid_content));

    close(bid_fd);
    free(filelist);

    // Update User Bidded
    sprintf(path,"USERS/%d/BIDDED/%03d.txt",uid,aid);
    create_file(path,"");

    sprintf(return_msg, "RBD OK\n");
    return 1;
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
        tcp_bid(fd, return_msg);
    }

    printf("SERVER MSG: %s", return_msg);
    n = write(fd, return_msg, strlen(return_msg));
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

    // Set the next AID to the last existing AID + 1
    char a_path[256];
    while (1) {
        sprintf(a_path, "%s/AUCTIONS/%03d", proj_path, next_aid);
        if (is_Directory_Exists(a_path))
            next_aid++;
        else
            break;
    }
    if (DEBUG) printf("Found %d auctions.\n", next_aid > 0 ? next_aid - 1 : 0);

    fd_set fds, fds_ready;
    FD_ZERO(&fds);
    FD_SET(fd_udp, &fds);
    FD_SET(fd_tcp, &fds);
    max_fd = (fd_tcp > fd_udp) ? fd_tcp : fd_udp;

    /* Loop para receber bytes e processá-los */
    while (1) {
        memset(msg, 0, BUF_SIZE);
        fds_ready = fds;

        // Debugging fd list
        if (DEBUG) printf("File descriptors: ");
        for (int k = 0; k < max_fd + 1; k++) {
            if (FD_ISSET(k, &fds_ready)) {
                if (DEBUG) printf("%d ", k);
            }
        }
        if (DEBUG) printf("\n");
        fflush(stdout);

        if (select(max_fd + 1, &fds_ready, NULL, NULL, NULL) < 0) return -1;
        for (int i = 0; i <= max_fd; i++) {
            if (FD_ISSET(i, &fds_ready)) {
                if (DEBUG) printf("Socket %d pronto para ler\n", i);
                if (i == fd_udp)  // socket do udp pronto a ler
                    handle_udp();
                else if (i == fd_tcp) {     // socket do tcp pronto a ler;
                    fd_new = accept_tcp();  // retorna socket novo (específico à
                                            // comunicação) depois de aceitar;
                    max_fd = fd_new;
                    if (DEBUG) printf("Socket %d aceite\n", fd_new);
                    FD_SET(fd_new, &fds);  // adiciona ao set de FDs
                } else {
                    if (DEBUG) printf("Handling socket %d...\n", i);
                    int h = handle_tcp(i);
                    if (DEBUG) printf("Finished handling\n");
                    // close(i);
                    FD_CLR(i, &fds);
                }
            }
        }
    }

    freeaddrinfo(res_udp);
    freeaddrinfo(res_tcp);
    close(fd_udp);
    close(fd_tcp);
}