#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define DEBUG 0
#define BUF_SIZE 128
#define A_DESC_MAX_LEN 10
#define A_START_VALUE_MAX_LEN 6
#define A_DURATION_MAX_LEN 5
#define A_FILENAME_MAX_LEN 24
#define A_FILE_SIZE_MAX_VALUE 10000000
#define A_FILE_SIZE_MAX_LEN 8
#define PASSWORD_SIZE 9
char port[8] = "58051";  // change ????
int verbose = 0;

int fd_udp = -1, fd_tcp = -1, next_aid = 0, max_fd = 0;
ssize_t n;
socklen_t addrlen;
struct addrinfo hints_udp, hints_tcp, *res_udp, *res_tcp;
struct sockaddr_in addr;
char buffer[BUF_SIZE];
char msg[1024];
char proj_path[128] = "";
fd_set fds;

void int_handler() {
    for (int i = 0; i <= max_fd; i++) {
        if (FD_ISSET(i, &fds)) {
            close(i);
        }
    }
    exit(0);
}

int valid_aid(int aid) { return aid >= 0 && aid <= 999; }

int input_verified(int uid, char *password) {
    // Count the number of digits in the entered number
    int count_digits = 0;
    int temp = uid;  // Temporary variable to store the number

    while (temp != 0) {
        temp /= 10;
        ++count_digits;
    }

    if (count_digits != 6) {
        return 0;
    }

    if (strcmp(password, "") != 0) {
        if (strlen(password) != 8) {
            return 0;
        }
        while (*password) {
            if (!isalnum(*password)) {
                return 0;  // Not alphanumeric
            }
            password++;
        }
        // All characters are alphanumeric
    }

    return 1;
}

int message_ended(char *buf, int size) {
    for (int i = 0; i < size; i++) {
        if (buf[i] == '\n' && i < size - 1)
            if (buf[i + 1] == '\n') return 1;
    }
    return 0;
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
        ret = mkdir("USERS", 0777);
        if (ret == -1) return -1;
    }
    sprintf(path, "%s/AUCTIONS", proj_path);
    if (!is_Directory_Exists(path)) {
        ret = mkdir("AUCTIONS", 0777);
        if (ret == -1) return -1;
    }
    return 0;
}

int check_auction_timeout(int aid) {
    char temp_path[128], file_content[256], datetime[128];
    long timeactive;
    int fd;

    // Get start file contents
    time_t time_start;
    sprintf(temp_path, "%s/AUCTIONS/%03d/START_%03d.txt", proj_path, aid, aid);
    if ((fd = open(temp_path, O_RDONLY)) == -1) return -1;
    read(fd, file_content, 128);
    sscanf(file_content, "%*d %*s %*s %*d %ld %*s %*s %ld", &timeactive,
           &time_start);
    close(fd);

    time_t time_now;
    time(&time_now);
    struct tm *time_info;
    time_info = localtime(&time_now);
    strftime(datetime, 128, "%Y-%m-%d %X", time_info);

    if (time_now > time_start + timeactive) {
        sprintf(temp_path, "%s/AUCTIONS/%03d/END_%03d.txt", proj_path, aid,
                aid);
        if ((fd = open(temp_path, O_WRONLY | O_CREAT, 0777)) == -1) return -1;
        sprintf(file_content, "%s %ld\n", datetime, time_now - time_start);
        write(fd, file_content, strlen(file_content));
        close(fd);

        return 1;
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
    char login_path[BUF_SIZE];
    sprintf(login_path, "USERS/%d/%d_login.txt", uid, uid);
    int file_exists = is_File_Exists(login_path);
    return file_exists;
}

int password_correct(int uid, char *password) {
    char path[128], temp[9] = "";
    sprintf(path, "%s/USERS/%03d/%03d_pass.txt", proj_path, uid, uid);
    int start_fd;
    start_fd = open(path, O_RDONLY);
    read(start_fd, temp, 8);
    close(start_fd);
    puts(temp);
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
                sprintf(msg, "RLI OK\n\n");
            } else {
                // User not logged in correctly
                sprintf(msg, "RLI NOK\n\n");
            }
        }

        else {
            // User was unregistered
            txt1 = create_file(pass_path, password);
            if (txt1 == -1) return -1;

            txt2 = create_file(login_path, "");
            if (txt2 == -1) return -1;
            sprintf(msg, "RLI REG\n\n");
        }
    } else {
        // Never registered before
        int ret;
        char hosted_path[BUF_SIZE];
        char bidded_path[BUF_SIZE];
        sprintf(uid_path, "USERS/%d", uid);
        sprintf(hosted_path, "USERS/%d/HOSTED", uid);
        sprintf(bidded_path, "USERS/%d/BIDDED", uid);

        ret = mkdir(uid_path, 0777);
        if (ret == -1) return -1;

        ret = mkdir(hosted_path, 0777);
        if (ret == -1) return -1;

        ret = mkdir(bidded_path, 0777);
        if (ret == -1) return -1;

        txt1 = create_file(pass_path, password);
        if (txt1 == -1) return -1;

        txt2 = create_file(login_path, "");
        if (txt2 == -1) return -1;

        sprintf(msg, "RLI REG\n\n");
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
                sprintf(msg, "RLO OK\n\n");
            } else {
                // User is not logged in
                sprintf(msg, "RLO NOK\n\n");
            }
        } else {
            // User was unregistered
            sprintf(msg, "RLO UNR\n\n");
        }
    } else {
        // User was never registered
        sprintf(msg, "RLO UNR\n\n");
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
                sprintf(msg, "RUR OK\n\n");
            } else {
                // User is not logged in
                sprintf(msg, "RUR NOK\n\n");
            }
        } else {
            // User was unregistered
            sprintf(msg, "RUR UNR\n\n");
        }
    } else {
        // User was never registered
        sprintf(msg, "RUR UNR\n\n");
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
    hints_udp.ai_flags = AI_PASSIVE;

    if (getaddrinfo(NULL, port, &hints_udp, &res_udp) != 0) exit(1);

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

    if (getaddrinfo(NULL, port, &hints_tcp, &res_tcp) != 0) exit(1);

    if (bind(fd_tcp, res_tcp->ai_addr, res_tcp->ai_addrlen) == -1) exit(1);
    if (listen(fd_tcp, 10) < 0) exit(1);

    return 0;
}

int show_record(int aid) {
    char temp_path[128], file_content[128], auction_name[A_DESC_MAX_LEN + 1],
        asset_fname[A_FILENAME_MAX_LEN + 1], start_datetime[128], temp[16];
    int start_fd, uid, start_value, timeactive, n, bid_fd;
    long sec_time;

    sprintf(temp_path, "%s/AUCTIONS/%03d/START_%03d.txt", proj_path, aid, aid);
    if (!is_File_Exists(temp_path)) {
        sprintf(msg, "RRC NOK\n\n");
        return 0;
    }

    // Get start file contents
    time_t time_start;
    sprintf(temp_path, "%s/AUCTIONS/%03d/START_%03d.txt", proj_path, aid, aid);
    if ((start_fd = open(temp_path, O_RDONLY)) == -1) return -1;
    read(start_fd, file_content, 128);
    sscanf(file_content, "%d %s %s %d %d %*s %*s %ld", &uid, auction_name,
           asset_fname, &start_value, &timeactive, &time_start);
    close(start_fd);

    struct tm *time_info;
    time(&time_start);
    time_info = localtime(&time_start);
    strftime(start_datetime, 128, "%Y-%m-%d %X", time_info);

    // Send response
    sprintf(msg, "RRC OK %d %s %s %d %s %d\n", uid, auction_name, asset_fname,
            start_value, start_datetime, timeactive);
    n = sendto(fd_udp, msg, strlen(msg), 0, (struct sockaddr *)&addr, addrlen);
    if (DEBUG) printf("SERVER MSG: %s", msg);
    if (n == -1) return -1;

    // List bids
    struct dirent **filelist;
    int n_entries;
    sprintf(temp_path, "%s/AUCTIONS/%03d/BIDS/", proj_path, aid);
    n_entries = scandir(temp_path, &filelist, 0, alphasort);
    /* printf("files: %d\n",n_entries);
    for(int k = 0; k < n_entries; k++) {
        printf("\t%s\n",filelist[k]->d_name);
    } */
    int last_50 = 0;
    if (n_entries < 0) return -1;
    if (n_entries > 2) {
        for (int f = n_entries - 1; f >= 0 && last_50 < 49; f--) {
            if (sscanf(filelist[f]->d_name, "%06d.txt", &start_value) != 1)
                continue;
            sprintf(temp_path, "%s/AUCTIONS/%03d/BIDS/%s", proj_path, aid,
                    filelist[f]->d_name);
            if ((bid_fd = open(temp_path, O_RDONLY)) == -1) return -1;
            memset(file_content, 0, sizeof(file_content));
            read(bid_fd, file_content, 128);
            sscanf(file_content, "%06d %d %s %s %ld", &uid, &start_value,
                   start_datetime, temp, &sec_time);

            sprintf(msg, "B %d %d %s %s %ld\n", uid, start_value,
                    start_datetime, temp, sec_time);
            close(bid_fd);
            n = sendto(fd_udp, msg, strlen(msg), 0, (struct sockaddr *)&addr,
                       addrlen);
            if (DEBUG) printf("SERVER MSG: %s", msg);
            if (n == -1) return -1;
            last_50++;
        }
    }

    // Send end message if auction ended
    sprintf(temp_path, "%s/AUCTIONS/%03d/END_%03d.txt", proj_path, aid, aid);
    if (is_File_Exists(temp_path)) {
        if ((bid_fd = open(temp_path, O_RDONLY)) == -1) return -1;
        memset(file_content, 0, sizeof(file_content));
        read(bid_fd, file_content, 128);

        sprintf(msg, "E %s\n", file_content);
        n = sendto(fd_udp, msg, strlen(msg), 0, (struct sockaddr *)&addr,
                   addrlen);
        if (DEBUG) printf("SERVER MSG: %s", msg);
        if (n == -1) return -1;
    }
    n = sendto(fd_udp, "\n\n", 2, 0, (struct sockaddr *)&addr, addrlen);
    return 0;
}

int my_bids(int uid) {
    char temp_path[128];
    int aid;

    if (!is_logged_in(uid)) {
        sprintf(msg, "RMB NLG\n\n");
        return 0;
    }

    sprintf(msg, "RMB OK");
    // List bids
    struct dirent **filelist;
    int n_entries;
    sprintf(temp_path, "%s/USERS/%03d/BIDDED", proj_path, uid);
    n_entries = scandir(temp_path, &filelist, 0, alphasort);

    if (n_entries < 0)
        return -1;
    else if (n_entries == 2) {
        sprintf(msg, "RMB NOK\n\n");
        return 0;
    }
    for (int f = 0; f < n_entries; f++) {
        if (sscanf(filelist[f]->d_name, "%03d.txt", &aid) != 1) continue;

        sprintf(temp_path, "%s/AUCTIONS/%03d/END_%03d.txt", proj_path, aid,
                aid);

        int ended = is_File_Exists(temp_path);
        if (!ended) ended = check_auction_timeout(aid);
        sprintf(msg, "%s %03d %d", msg, aid, !ended);
        if (DEBUG) printf("SERVER MSG: %s", msg);
        if (n == -1) return -1;
    }
    sprintf(msg, "%s\n\n", msg);
    n = sendto(fd_udp, msg, strlen(msg), 0, (struct sockaddr *)&addr, addrlen);
    return 0;
}

int my_auctions(int uid) {
    char temp_path[128];
    char aux[128];
    int aid;

    if (!is_logged_in(uid)) {
        sprintf(msg, "RMA NLG\n\n");
        return 0;
    }

    // List auctions
    struct dirent **filelist;
    int n_entries;
    sprintf(temp_path, "%s/USERS/%03d/HOSTED", proj_path, uid);
    n_entries = scandir(temp_path, &filelist, 0, alphasort);

    if (n_entries < 0)
        return -1;
    else if (n_entries == 2) {
        sprintf(msg, "RMA NOK\n\n");
        return 0;
    }
    sprintf(msg, "RMA OK");
    for (int f = 0; f < n_entries; f++) {
        if (sscanf(filelist[f]->d_name, "%03d.txt", &aid) != 1) continue;

        sprintf(temp_path, "%s/AUCTIONS/%03d/END_%03d.txt", proj_path, aid,
                aid);

        int ended = is_File_Exists(temp_path);
        if (!ended) ended = check_auction_timeout(aid);
        sprintf(aux, " %03d %d", aid, !ended);

        strcat(msg, aux);
    }
    strcat(msg, "\n\n");
    n = sendto(fd_udp, msg, strlen(msg), 0, (struct sockaddr *)&addr, addrlen);
    if (n == -1) return -1;
    return 0;
}

int list_auctions() {
    char temp_path[128];
    int aid;
    // List auctions
    struct dirent **filelist;
    int n_entries;
    sprintf(temp_path, "%s/AUCTIONS", proj_path);
    n_entries = scandir(temp_path, &filelist, 0, alphasort);
    if (n_entries < 0)
        return -1;
    else if (n_entries == 2) {
        sprintf(msg, "RLS NOK\n\n");
        return 0;
    }
    sprintf(msg, "RLS OK");
    for (int f = 0; f < n_entries; f++) {
        if (sscanf(filelist[f]->d_name, "%03d", &aid) != 1) continue;
        sprintf(temp_path, "%s/AUCTIONS/%03d/END_%03d.txt", proj_path, aid,
                aid);
        int ended = check_auction_timeout(aid);
        sprintf(msg, "%s %s %d", msg, filelist[f]->d_name, !ended);
    }
    sprintf(msg, "%s\n\n", msg);

    return 0;
}

int handle_udp() {
    int aux = -1, n, uid;
    addrlen = sizeof(addr);
    char temp[BUF_SIZE];
    char password[32];

    n = recvfrom(fd_udp, buffer, BUF_SIZE, 0, (struct sockaddr *)&addr,
                 &addrlen);
    if (n == -1) return -1;
    if (verbose)
        printf("New UDP request | IP: %s | Port: %d\n",
               inet_ntoa(addr.sin_addr), (int)ntohs(addr.sin_port));
    if (DEBUG) printf("UDP | Received %d bytes | %s\n", n, buffer);
    // TODO: INTERPRETAR MENSAGENS DO CLIENTE
    sscanf(buffer, "%s ", temp);
    if (!strcmp(temp, "LIN")) {
        // login
        if (sscanf(buffer, "LIN %d %s", &uid, password) == 2 &&
            input_verified(uid, password)) {
            aux = login_user(uid, password);
            if (aux == -1) {
                memset(msg, 0, sizeof msg);
                sprintf(msg, "RLI");
            }
        }
    } else if (!strcmp(temp, "LOU")) {
        // logout
        if (sscanf(buffer, "LOU %d %s", &uid, password) == 2 &&
            input_verified(uid, password)) {
            aux = logout_user(uid);
            if (aux == -1) {
                memset(msg, 0, sizeof msg);
                sprintf(msg, "RLO");
            }
        }
    }

    else if (!strcmp(temp, "UNR")) {
        // unregister
        if (sscanf(buffer, "UNR %d %s", &uid, password) == 2 &&
            input_verified(uid, password)) {
            aux = unregister_user(uid);
            if (aux == -1) {
                memset(msg, 0, sizeof msg);
                sprintf(msg, "RUR");
            }
        }
    } else if (!strcmp(temp, "SRC")) {
        int aid;
        if (sscanf(buffer, "SRC %d", &aid) == 1 && valid_aid(aid)) {
            aux = show_record(aid);
        }
        if (aux == -1) {
            memset(msg, 0, sizeof msg);
            sprintf(msg, "RRC");
        }
    } else if (!strcmp(temp, "LMA")) {
        int uid;
        if (sscanf(buffer, "LMA %d", &uid) == 1 && input_verified(uid, "")) {
            aux = my_auctions(uid);
        }
        if (aux == -1) {
            memset(msg, 0, sizeof msg);
            sprintf(msg, "RMA");
        }
    } else if (!strcmp(temp, "LMB")) {
        int uid;
        if (sscanf(buffer, "LMB %d", &uid) == 1 && input_verified(uid, "")) {
            aux = my_bids(uid);
        }
        if (aux == -1) {
            memset(msg, 0, sizeof msg);
            sprintf(msg, "RMB");
        }
    } else if (!strcmp(temp, "LST")) {
        aux = list_auctions();
        if (aux == -1) {
            memset(msg, 0, sizeof msg);
            sprintf(msg, "RST");
        }
    } else {
        aux = -1;
    }

    // implement the other udp commands
    if (aux == -1) {
        sprintf(msg, "%s ERR\n\n", msg);  // CHECK??
    }

    if (DEBUG) printf("SERVER MSG: %s", msg);
    n = sendto(fd_udp, msg, strlen(msg), 0, (struct sockaddr *)&addr, addrlen);

    if (n == -1) return -1;
    return 0;
}

int download_file(int fd, char *fpath, int fsize) {
    char downloaded[BUF_SIZE];
    int new_file = open(fpath, O_WRONLY | O_TRUNC | O_CREAT, 0777);
    memset(downloaded, 0, BUF_SIZE);
    if (DEBUG) printf("Created file %s, writing...\n", fpath);

    while (fsize > 0) {
        memset(downloaded, 0, BUF_SIZE);
        n = read(fd, downloaded, 127);
        /* if (DEBUG) puts(downloaded); */
        if (n == -1) {
            if (DEBUG)
                printf("TCP | Error downloading file (connected) %d\n", fd);
            return -1;
        }
        n = write(new_file, downloaded, n);
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
    if (DEBUG)
        printf("Finished writing file %s (%ld bytes)\n", fpath,
               get_file_size(fpath));
    return 0;
}

int tcp_opa(int fd, char *return_msg) {
    char fname[128], aname[A_DESC_MAX_LEN + 1], password[128], a_dir[256];
    int uid, timeactive, fsize, start_value;

    if (sscanf(buffer, "OPA %d %s %s %d %d %s %d", &uid, password, aname,
               &start_value, &timeactive, fname, &fsize) != 7 ||
        !input_verified(uid, password) || strlen(aname) > 10 ||
        start_value > 999999 || timeactive > 99999 || strlen(fname) > 24 ||
        fsize > 99999999)
        return -1;
    if (!password_correct(uid, password))  // TODO
        return 0;
    if (!is_logged_in(uid)) {
        sprintf(return_msg, "ROA NLG\n\n");
        return 0;
    }

    sprintf(a_dir, "%s/AUCTIONS/%03d", proj_path, next_aid);
    while (is_Directory_Exists(a_dir)) {
        next_aid++;
        sprintf(a_dir, "%s/AUCTIONS/%03d", proj_path, next_aid);
    }
    // Create auction AID directory
    mkdir(a_dir, 0777);
    if (DEBUG) puts("Created auction folder. ");

    char file_path[256];
    sprintf(file_path, "%s/AUCTIONS/%03d/ASSET", proj_path, next_aid);
    mkdir(file_path, 0777);

    // Download asset file
    sprintf(file_path, "%s/AUCTIONS/%03d/ASSET/%s", proj_path, next_aid, fname);
    if (download_file(fd, file_path, fsize) == -1) return -1;

    // Create START file
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
    mkdir(file_path, 0777);
    if (DEBUG) puts("Created bids folder.\n");

    // Update User Hosted
    sprintf(file_path, "USERS/%d/HOSTED/%03d.txt", uid, next_aid);
    create_file(file_path, "");

    sprintf(return_msg, "ROA OK %03d\n\n", next_aid);
    // write(fd, return_msg, 127);
    next_aid++;
    return 1;
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
    if (sscanf(buffer, "CLS %d %s %d", &uid, password, &aid) != 3 ||
        !input_verified(uid, password) || !valid_aid(aid))
        return -1;
    if (!is_logged_in(uid)) {
        sprintf(return_msg, "RCL NLG\n\n");
    } else if (!auction_exists(aid)) {
        sprintf(return_msg, "RCL EAU\n\n");
    } else if (!auction_owned_by(aid, uid)) {
        sprintf(return_msg, "RCL EOW\n\n");
    } else if (auction_ended(aid)) {
        sprintf(return_msg, "RCL END\n\n");
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

    sprintf(return_msg, "RCL OK\n\n");

    return 0;
}

int tcp_sas(int fd, char *return_msg) {
    int aid, remaining, start_fd;
    char fbuf[128] = "", fname[128] = "", fpath[128] = "", start_content[128];
    long fsize;
    memset(fbuf, 0, 128);

    if (sscanf(buffer, "SAS %d", &aid) != 1 || !valid_aid(aid)) return -1;
    if (!auction_exists(aid)) return -1;

    sprintf(fpath, "AUCTIONS/%03d/START_%03d.txt", aid, aid);
    if ((start_fd = open(fpath, O_RDONLY)) == -1) return -1;
    read(start_fd, start_content, 128);
    sscanf(start_content, "%*d %*s %s", fname);
    close(start_fd);

    sprintf(fpath, "AUCTIONS/%03d/ASSET/%s", aid, fname);
    if (!is_File_Exists(fpath)) return -1;
    check_auction_timeout(aid);
    fsize = get_file_size(fpath);
    sprintf(return_msg, "RSA OK %s %ld\n", fname, fsize);
    /* n = write(fd, return_msg, strlen(return_msg) + 1);
    if (n == -1) {
        if (DEBUG) printf("TCP | Error writing in socket (connected) %d\n", fd);
        return -1;
    } */

    // Send file
    int file_to_send;
    if ((file_to_send = open(fpath, O_RDONLY)) < 0) return -1;
    remaining = fsize;

    n = write(fd, return_msg, strlen(return_msg));
    if (DEBUG) printf("SERVER_MSG: %s", return_msg);
    if (n == -1) {
        if (DEBUG) printf("TCP | Error writing asset (connected) %d\n", fd);
        return -1;
    }

    while (remaining > 0) {
        memset(fbuf, 0, BUF_SIZE);
        if (DEBUG)
            printf("show_asset: Sending file %s | %d bytes remaining \n", fname,
                   remaining);
        n = read(file_to_send, fbuf, BUF_SIZE - 1);
        if (n == -1) {
            if (DEBUG) printf("TCP | Error reading asset (connected) %d\n", fd);
            return -1;
        }

        n = write(fd, fbuf, n);
        if (n == -1) {
            if (DEBUG) printf("TCP | Error writing asset (connected) %d\n", fd);
            return -1;
        }
        remaining -= n;
    }

    /* n = write(fd, "\n\n", 2); */
    close(file_to_send);
    return 0;
}

int tcp_bid(char *return_msg) {
    char password[PASSWORD_SIZE], path[256], bid_content[128], datetime[128],
        start_content[128];
    int uid, aid, value, highest_bid, start_fd;

    if (sscanf(buffer, "BID %d %s %d %d", &uid, password, &aid, &value) != 4 ||
        !input_verified(uid, password) || !valid_aid(aid)) {
        if (DEBUG) puts("ERROR: bid sscanf");
        return -1;
        /* } else if (!password_correct(uid, password)) {
            if (DEBUG) puts("Password incorrect");
            sprintf(return_msg, "RBD NOK\n"); */
    } else if (!is_logged_in(uid)) {
        sprintf(return_msg, "RBD NLG\n\n");
    } else if (auction_owned_by(aid, uid)) {
        sprintf(return_msg, "RBD ILG\n\n");
    } else if (!auction_exists(aid) || auction_ended(aid) ||
               check_auction_timeout(aid)) {
        sprintf(return_msg, "RBD NOK\n\n");
    }
    // Uma das condições acima foi encontrada
    if (strlen(return_msg) != 0) return 0;

    // Check if higher bid exists
    struct dirent **filelist;
    int n_entries;
    sprintf(path, "%s/AUCTIONS/%03d/BIDS/", proj_path, aid);
    n_entries = scandir(path, &filelist, 0, alphasort);
    if (n_entries <= 0) {
        return -1;
    }
    if (n_entries > 2) {
        sscanf(filelist[n_entries - 1]->d_name, "%06d.txt", &highest_bid);
        if (value <= highest_bid) {  // bid inferior
            sprintf(return_msg, "RBD REF\n\n");
            return 0;
        }
    } else {
        sprintf(path, "%s/AUCTIONS/%03d/START_%03d.txt", proj_path, aid, aid);
        if ((start_fd = open(path, O_RDONLY)) == -1) return -1;
        read(start_fd, start_content, 128);
        int start_value;
        sscanf(start_content, "%*d %*s %*s %d %*d %*s %*s %*ld", &start_value);
        close(start_fd);

        if (value < start_value) {
            sprintf(return_msg, "RBD REF\n\n");
            return 0;
        }
    }

    // Create file
    int bid_fd;
    sprintf(path, "%s/AUCTIONS/%03d/BIDS/%06d.txt", proj_path, aid, value);
    if ((bid_fd = open(path, O_WRONLY | O_CREAT, 0777)) == -1) {
        puts("ERROR: Could not create file.");
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
    sprintf(path, "USERS/%d/BIDDED/%03d.txt", uid, aid);
    create_file(path, "");

    sprintf(return_msg, "RBD ACC\n\n");
    return 1;
}

int handle_tcp(int fd) {
    int aux, sa = 0;
    char temp[BUF_SIZE];
    char return_msg[BUF_SIZE] = "";

    n = read(fd, buffer, BUF_SIZE);
    if (n == -1) {
        if (DEBUG) printf("TCP | Error reading socket (connected) %d\n", fd);
        return -1;
    }

    if (DEBUG)
        printf("TCP | fd:%d\t| Received %zd bytes | %s\n", fd, n, buffer);
    sscanf(buffer, "%s ", temp);
    if (!strcmp(temp, "OPA")) {
        aux = tcp_opa(fd, return_msg);
        if (aux == 0) {
            sprintf(return_msg, "ROA NOK\n\n");
        } else if (aux == -1) {
            memset(return_msg, 0, sizeof return_msg);
            sprintf(return_msg, "ROA ERR\n\n");
        }
    } else if (!strcmp(temp, "CLS")) {
        aux = tcp_cls(return_msg);
        if (aux == -1) {
            memset(return_msg, 0, sizeof return_msg);
            sprintf(return_msg, "RCL ERR\n\n");
        }
    } else if (!strcmp(temp, "SAS")) {
        sa = 1;
        aux = tcp_sas(fd, return_msg);
        if (aux == -1) {
            memset(return_msg, 0, sizeof return_msg);
            sprintf(return_msg, "RSA ERR\n\n");
        }
        return aux > 0;
    } else if (!strcmp(temp, "BID")) {
        aux = tcp_bid(return_msg);
        if (aux == -1) {
            memset(return_msg, 0, sizeof return_msg);
            sprintf(return_msg, "RBD ERR\n\n");
        }
    }

    if (!sa) {
        if (DEBUG) printf("SERVER MSG: %s", return_msg);
        n = write(fd, return_msg, strlen(return_msg));
        if (n == -1) {
            if (DEBUG)
                printf("TCP | Error writing in socket (connected) %d\n", fd);
            return -1;
        }
    }

    n = read(fd, return_msg, BUF_SIZE);

    if (message_ended(return_msg, BUF_SIZE)) {
        close(fd);
        fd = -1;
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
    if (verbose)
        printf("New TCP request | IP: %s | Port: %d\n",
               inet_ntoa(addr.sin_addr), (int)ntohs(addr.sin_port));

    if (DEBUG) printf("TCP | Accepted fd: %d\n", newfd);
    return newfd;
}

int main(int argc, char **argv) {
    signal(SIGINT, int_handler);
    if (argc > 1) {
        for (int i = 1; i < argc && i < 4; i += 2) {
            if (!strcmp(argv[i], "-n") && (argc > i + 1)) {
                strcpy(port, argv[i + 1]);
            }
            if (!strcmp(argv[i], "-v")) {
                verbose = 1;
            }
        }
    }

    int fd_new;
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

    fd_set fds_ready;
    FD_ZERO(&fds);
    FD_SET(fd_udp, &fds);
    FD_SET(fd_tcp, &fds);
    max_fd = (fd_tcp > fd_udp) ? fd_tcp : fd_udp;

    /* Loop para receber bytes e processá-los */
    while (1) {
        memset(msg, 0, BUF_SIZE);
        memset(buffer, 0, BUF_SIZE);
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
                    handle_tcp(i);
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