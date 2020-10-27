#define _GNU_SOURCE
#include <sys/types.h>
#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <netdb.h>
#include <sys/select.h>
#include <sys/syslog.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <pthread.h>

#define BUFSIZE 65536
#define IPSIZE 4
#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))
#define ARRAY_INIT    {0}
#define TLS_HS_REC_HDR_V1   "\x16\x03\x01"
#define BAD_SITE "youtube"

/*Socks versions definitions*/
#define VERSION5  0x05
#define VERSION4  0x04 
#define RESERVED  0x0

/*Socks auth methods definitions*/
#define NOAUTH 0x00
#define NOMETHOD 0xff
#define USERPASS 0x02

/*Socks command definitions*/
#define CONNECT 0x01

/*Sock command_type definitions*/
#define IP 0x01
#define DOMAIN 0x03

unsigned short int port = 1080;// SOCKS server default port ( RFC1928)

enum socks_status {
	OK = 0x00,
	FAILED = 0x05
};

char *pattern_find (char *string1, const char *string2) {
    char *a = string1, *b = string2;
    for (;;)
    if (!*b)
    return (char *)string1;
    else if (!*a)
    return NULL;
    else if (*a++ != *b++) {
    a = ++string1; b = string2;
    }
}



void plog(const char *format, ...)
{
    va_list ap;

    va_start(ap, format);

        vfprintf(stderr, format, ap);
        fprintf(stderr, "\n");
    
    va_end(ap);
}


int readn(int fd, void *buf, int n)
{
    int nread, left = n;
    while (left > 0) {
        if ((nread = read(fd, buf, left)) == -1) {
            if (errno == EINTR || errno == EAGAIN) {
                continue;
            }
        } else {
            if (nread == 0) {
                return 0;
            } else {
                left -= nread;
                buf += nread;
            }
        }
    }
    return n;
}

int writen(int fd, void *buf, int n)
{
    int nwrite, left = n;
    while (left > 0) {
        if ((nwrite = write(fd, buf, left)) == -1) {
            if (errno == EINTR || errno == EAGAIN) {
                continue;
            }
        } else {
            if (nwrite == n) {
                return 0;
            } else {
                left -= nwrite;
                buf += nwrite;
            }
        }
    }
    return n;
}

void app_thread_exit(int ret, int fd)
{
    close(fd);
    pthread_exit((void *)&ret);
}

int app_connect(int type, void *buf, unsigned short int portnum)
{
    int fd;
    struct sockaddr_in remote;
    char address[16];
    char *pstart;

    memset(address, 0, ARRAY_SIZE(address));

    if (type == IP) {
        char *ip = (char *)buf;
        snprintf(address, ARRAY_SIZE(address), "%hhu.%hhu.%hhu.%hhu",
        ip[0], ip[1], ip[2], ip[3]);
        memset(&remote, 0, sizeof(remote));
        remote.sin_family = AF_INET;
        remote.sin_addr.s_addr = inet_addr(address);
        remote.sin_port = htons(portnum);

        fd = socket(AF_INET, SOCK_STREAM, 0);
        if (connect(fd, (struct sockaddr *)&remote, sizeof(remote)) < 0) {
            //plog("connect() in app_connect");    //log_message("connect() in app_connect");
            close(fd);
            return -1;
        }

        return fd;
    } else if (type == DOMAIN) {
         
        char portaddr[6];
        struct addrinfo *res;
        snprintf(portaddr, ARRAY_SIZE(portaddr), "%d", portnum);
        //plog("getaddrinfo: %s %s", (char *)buf, portaddr); //log_message("getaddrinfo: %s %s", (char *)buf, portaddr);

        int ret = getaddrinfo((char *)buf, portaddr, NULL, &res);
        if ((pattern_find(buf, BAD_SITE)) != NULL){               
        plog("YOUTUBE WAS BLOCKED");
        close(fd);
        return -1;
        }


        if (ret == EAI_NODATA) {
            return -1;
        } else if (ret == 0) {
            struct addrinfo *r;
            for (r = res; r != NULL; r = r->ai_next) {
    fd = socket(r->ai_family, r->ai_socktype,
					    r->ai_protocol);
                if (fd == -1) {
                            continue;
                }
                ret = connect(fd, r->ai_addr, r->ai_addrlen);
                if (ret == 0) {
                    freeaddrinfo(res);
                    return fd;
                } else {
                    close(fd);
                }
            }
        }
        freeaddrinfo(res);
        return -1;
    }

    return -1;
}

int socks_invitation(int fd, int *version)
{
    char init[2];
    int nread = readn(fd, (void *)init, ARRAY_SIZE(init));
    if (nread == 2 && init[0] != VERSION5 && init[0] != VERSION4) {
    //plog("They send us %hhX %hhX", init[0], init[1]);   
    //plog("Incompatible version!");                
        app_thread_exit(0, fd);
    }
    //plog("Initial %hhX %hhX", init[0], init[1]);         
    *version = init[0];
    return init[1];
}

int socks5_auth_noauth(int fd)
{
    char answer[2] = { VERSION5, NOAUTH };
    writen(fd, (void *)answer, ARRAY_SIZE(answer));
    return 0;
}

void socks5_auth_notsupported(int fd)
{
    char answer[2] = { VERSION5, NOMETHOD };
    writen(fd, (void *)answer, ARRAY_SIZE(answer));
}

void socks5_auth(int fd, int methods_count)
{
    int supported = 0;
    int num = methods_count;
    char auth_type,type;
    for (int i = 0; i < num; i++) {
        //char type; vvi 25102020
        readn(fd, (void *)&type, 1);
        //plog("Method AUTH %hhX", type);   //log_message("Method AUTH %hhX", type);
        if ((type == NOAUTH) || (type == USERPASS)) {
            supported = 1;
        }
    }
    if (supported == 0) {
    socks5_auth_notsupported(fd);
        app_thread_exit(1, fd);
    }
    //vvi add 25102020
    auth_type = type;
    int ret = 0;
    switch (auth_type) {
    case NOAUTH:
        ret = socks5_auth_noauth(fd);
        break;
    }
    if (ret == 0) {
        return;
    } else {
        app_thread_exit(1, fd);
    }
}

int socks5_command(int fd)
{
    char command[4];
    readn(fd, (void *)command, ARRAY_SIZE(command));
    //plog("Command %hhX %hhX %hhX %hhX", command[0], command[1],
    //	    command[2], command[3]);
    return command[3];
}

unsigned short int socks_read_port(int fd)
{
	unsigned short int p;
	readn(fd, (void *)&p, sizeof(p));
	//plog("Port %hu", ntohs(p)); //log_message("Port %hu", ntohs(p));
	return p;
}

char *socks_ip_read(int fd)
{
    char *ip = (char *)malloc(sizeof(char) * IPSIZE);
    readn(fd, (void *)ip, IPSIZE);
    plog("IP %hhu.%hhu.%hhu.%hhu", ip[0], ip[1], ip[2], ip[3]); 
    return ip;
}

void socks5_ip_send_response(int fd, char *ip, unsigned short int port)
{
    char response[4] = { VERSION5, OK, RESERVED, IP };
    writen(fd, (void *)response, ARRAY_SIZE(response));
    writen(fd, (void *)ip, IPSIZE);
    writen(fd, (void *)&port, sizeof(port));
}

char *socks5_domain_read(int fd, unsigned char *size)
{
    unsigned char s;
    readn(fd, (void *)&s, sizeof(s));
    char *address = (char *)malloc((sizeof(char) * s) + 1);
    readn(fd, (void *)address, (int)s);
    address[s] = 0;
    plog("Address %s", address); 
    *size = s;
    return address;
}


void socks5_domain_send_response(int fd, char *domain, unsigned char size,
                 unsigned short int port)
{
    char response[4] = { VERSION5, OK, RESERVED, DOMAIN };
    writen(fd, (void *)response, ARRAY_SIZE(response));
    writen(fd, (void *)&size, sizeof(size));
    writen(fd, (void *)domain, size * sizeof(char));
    writen(fd, (void *)&port, sizeof(port));
}


void app_socket_pipe(int fd0, int fd1)
{
    int maxfd, ret;
    fd_set rd_set;
    size_t nread;
    char buffer_r[BUFSIZE];

   // plog("Connecting two sockets");  //log_message("Connecting two sockets");

    maxfd = (fd0 > fd1) ? fd0 : fd1;
    while (1) {
        FD_ZERO(&rd_set);
        FD_SET(fd0, &rd_set);
        FD_SET(fd1, &rd_set);
        ret = select(maxfd + 1, &rd_set, NULL, NULL, NULL);

        if (ret < 0 && errno == EINTR) {
            continue;
        }

        if (FD_ISSET(fd0, &rd_set)) {
            nread = recv(fd0, buffer_r, BUFSIZE, 0);
            if (nread <= 0)
                break;
            send(fd1, (const void *)buffer_r, nread, 0);
        }

        if (FD_ISSET(fd1, &rd_set)) {
            nread = recv(fd1, buffer_r, BUFSIZE, 0);
            if (nread <= 0)
                break;
            send(fd0, (const void *)buffer_r, nread, 0);
        }
    }
}

void *app_thread_process(void *fd)
{
    int net_fd = *(int *)fd;
    int version = 0;
    int inet_fd = -1;
    char methods = socks_invitation(net_fd, &version);

    switch (version) {
    case VERSION5: {
            socks5_auth(net_fd, methods);
            int command = socks5_command(net_fd);

            if (command == IP) {
                char *ip = socks_ip_read(net_fd);
                unsigned short int p = socks_read_port(net_fd);

                inet_fd = app_connect(IP, (void *)ip, ntohs(p));
                if (inet_fd == -1) {
                app_thread_exit(1, net_fd);
                }
                socks5_ip_send_response(net_fd, ip, p);
                free(ip);
                break;
            } else if (command == DOMAIN) {
                unsigned char size;
                char *address = socks5_domain_read(net_fd, &size);
                unsigned short int p = socks_read_port(net_fd);

                inet_fd = app_connect(DOMAIN, (void *)address, ntohs(p));
                if (inet_fd == -1) {
                    app_thread_exit(1, net_fd);
                }
                socks5_domain_send_response(net_fd, address, size, p);
                free(address);
                break;
            } else {
                app_thread_exit(1, net_fd);
            }
    }

    }

    app_socket_pipe(inet_fd, net_fd);
    close(inet_fd);
    app_thread_exit(0, net_fd);

    return NULL;
}

int app_loop()
{
    int sock_fd, net_fd;
    int optval = 1;
    struct sockaddr_in local, remote;
    socklen_t remotelen;
    if ((sock_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        plog("socket()"); 
        exit(1);
    }

    if (setsockopt
        (sock_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&optval,
        sizeof(optval)) < 0) {
        plog("setsockopt()"); 
        exit(1);
    }

    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_ANY);
    local.sin_port = htons(port);

    if (bind(sock_fd, (struct sockaddr *)&local, sizeof(local)) < 0) {
        plog("bind()"); 
        exit(1);
    }

    if (listen(sock_fd, 25) < 0) {
        plog("listen()");
        exit(1);
    }

    remotelen = sizeof(remote);
    memset(&remote, 0, sizeof(remote));

    plog("Listening port %d...", port); 

    pthread_t worker;
    while (1) {
        if ((net_fd =
            accept(sock_fd, (struct sockaddr *)&remote,
                &remotelen)) < 0) {
            plog("accept()"); 
            exit(1);
        }
        int one = 1;
        setsockopt(sock_fd, SOL_TCP, TCP_NODELAY, &one, sizeof(one));
        if (pthread_create
            (&worker, NULL, &app_thread_process,
            (void *)&net_fd) == 0) {
            pthread_detach(worker);
        } else {
            plog("pthread_create()"); 
        }
    }
}


void usage(char *app)
{
    printf
        ("USAGE: %s [-h][-n PORT][-a AUTHTYPE][-u USERNAME][-l LOGFILE]\n",
        app);
	//printf("AUTHTYPE: 0 for NOAUTH, 2 for USERPASS\n");
    printf
        ("By default: port is 1080, authtype is no auth, logfile is stdout\n");
    exit(1);
}

int main(int argc, char *argv[])
{
    int ret;

    signal(SIGPIPE, SIG_IGN);

    while ((ret = getopt(argc, argv, "n:l:h")) != -1) {
        switch (ret) {

        case 'n':{
                port = atoi(optarg) & 0xffff;
                break;
            }

        case 'h':
        default:
            usage(argv[0]);
        }
    }
    //plog("Starting with authtype %X", NOAUTH); 
    app_loop();
    return 0;
}


