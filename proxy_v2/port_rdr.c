#include <stdio.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <stdlib.h>
#include <netdb.h>
#include <signal.h>
#include <arpa/inet.h>


#define ERR_EXIT(msg) perror(msg); exit(1);

#define TLS_HS_REC_HDR_V1   "\x16\x03\x01" //TLS v1.0  signature

const char good_site[] = "coolsite.io";
const char bad_site[] = "badsite.io";
char server_name[255];

/***
*Return pointer to substring founded
*/
char *patern_find (char *string1, const char *string2) 
	{
      char *a = string1, *b = string2;
      for (;;)
        if      (!*b)          return (char *)string1;
        else if (!*a)          return NULL;
        else if (*a++ != *b++) {a = ++string1; b = string2;}
        }

/**
 * Send the traffic from src socket to dst socket
 *
 */
void transfer_data(int src, int dst) {
    char buffer[4096];
    int r, i, j;
    unsigned short cipher_size,shift, ext_size,server_name_size;
    char *pstart;
    r = read(src, buffer, 4096);
 
    if ((pstart = patern_find(buffer,TLS_HS_REC_HDR_V1)) !=NULL)
        {
    printf("TLS V1.0 header detected\n ");
    if(*(pstart + 5) == '\x01') 
    printf("Client Hello HS hdr identified\n");
        if(*(pstart+43) == '\x20') { //SID lenght found
    printf("SID len field found\n");    
    shift = 43+ (*(pstart + 43));//size 75; *(pstart+43) = 32 
    if(*(pstart+shift+1) == '\x00')
    printf("CFL field start:\n");	
    cipher_size = ntohs(*(unsigned short*)(pstart+shift+1));   
    printf("cipher_size:%d\n",cipher_size);
    shift += (cipher_size+5);//
    ext_size = ntohs(*(unsigned short*)(pstart+shift)); //was shift instead 116
    printf("ext_size:%d\n",ext_size);
	if((*(pstart+shift+2) == '\x00') && (*(pstart+shift+3) == '\x00')) //shift+2 must be 118 and 119
    printf("sni ext found\n");
    shift = shift+3+6;// server_name_len package 125
    server_name_size = ntohs(*(unsigned short*)(pstart + shift)); //was shift instead 116
    printf("server_name_size:%d\n",server_name_size); //11
    memcpy(server_name, (pstart+shift+2), server_name_size);
    printf("name of site: %s\n",server_name);
	}
	else printf("error occured\n");
	}

    while (r > 0) {
        i = 0;

        while (i < r) {
            j = write(dst, buffer + i, r - i);

            if (j == -1) {
                ERR_EXIT("write sock err");
            }

            i += j;
        }

        r = read(src, buffer, 4096);
    }

    if (r == -1) {
        ERR_EXIT("read");
    }

    shutdown(src, SHUT_RD);
    shutdown(dst, SHUT_WR);
    close(src);
    close(dst);
    exit(0);
}


/**
 * Opens a connection to the destination.
 *
 * On any error, this ERR_EXITs and will kill the forked process.
 */
int open_forwarding_socket(char *target_name, int target_port) {
    int forward_socket;
    struct hostent *forward;
    struct sockaddr_in forward_address;

    forward = gethostbyname(target_name);

    if (forward == NULL) {
        ERR_EXIT("gethostbyname");
    }

    bzero((char *) &forward_address, sizeof(forward_address));
    forward_address.sin_family = AF_INET;
    bcopy((char *)forward->h_addr, (char *) &forward_address.sin_addr.s_addr, forward->h_length);
    forward_address.sin_port = htons(target_port);

    forward_socket = socket(AF_INET, SOCK_STREAM, 0);

    if (forward_socket == -1) {
        ERR_EXIT("socket");
    }

    if (connect(forward_socket, (struct sockaddr *) &forward_address, sizeof(forward_address)) == -1) {
        ERR_EXIT("connect");
    }

    return forward_socket;
}


/**
 * Forwards all traffic from the client's socket to the destination
 * host/port.  This also initiates the connection to the destination.
 */
void forward_traffic(int client_socket, char *target_name, int target_port) {
    int forward_socket;
    pid_t down_pid;

    forward_socket = open_forwarding_socket(target_name, target_port);

    // Fork - child forwards traffic back to client, parent sends from client
    // to forwarded port
    down_pid = fork();

    if (down_pid == -1) {
        ERR_EXIT("fork");
    }

    if (down_pid == 0) {
        transfer_data(forward_socket, client_socket);
    } else {
        transfer_data(client_socket, forward_socket);
    }
}


/**
 * Opens own listening port.
 */
int open_listening_port(int own_port) {
    struct sockaddr_in server_address;
    int server_socket;

    server_socket = socket(AF_INET, SOCK_STREAM, 0);

    if (server_socket == -1) {
        ERR_EXIT("socket create err");
    }

    bzero((char *) &server_address, sizeof(server_address));
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = INADDR_ANY;
    server_address.sin_port = htons(own_port);

    if (bind(server_socket, (struct sockaddr *) &server_address, sizeof(server_address)) == -1) {
        ERR_EXIT("bind to sock err");
    }

    if (listen(server_socket, 40) == -1) {
        ERR_EXIT("listen error");
    }

    return server_socket;
}


/**
 * Handles a one connection.Fork in order to handle next
 * client.The child forward traffic.
 */
void accept_conn(int server_socket, char *target_name, int target_port) {
    int client_socket;
    pid_t up_pid;

    client_socket = accept(server_socket, NULL, NULL);

    if (client_socket == -1) {
        ERR_EXIT("accept connection err");
    }

    // Fork - Child handles this connection, but parent listens for another client
    up_pid = fork();

    if (up_pid == -1) {
        ERR_EXIT("fork");
    }

    if (up_pid == 0) {
        forward_traffic(client_socket, target_name, target_port);
        exit(1);
    }

    close(client_socket);
}


/**
 * Argument parsing and validation
 */
void check_cmdline(int argc, char **argv, int *own_port, char **target_name, int *target_port) {
    if (argc < 3) {
        fprintf(stderr, "Not enough arguments\n");
        fprintf(stderr, "Syntax:  %s listen_port forward_host [target_port]\n", argv[0]);
        exit(1);
    }

    *own_port = atoi(argv[1]);

    if (*own_port < 1) {
        fprintf(stderr, "Listen port is invalid\n");
        exit(1);
    }

    *target_name = argv[2];
    
    if (argc == 3) {
        *target_port = *own_port;
    } else {
        *target_port = atoi(argv[3]);

        if (*target_port < 1) {
            fprintf(stderr, "target port is invalid\n");
            exit(1);
        }
    }
}


/**
 *main cycle
 */
int main(int argc, char **argv) {
    
    int own_port, target_port, server_socket;
    char *target_name;
    bzero(server_name, sizeof(server_name));
    check_cmdline(argc, argv, &own_port, &target_name, &target_port);
    signal(SIGCHLD,  SIG_IGN);
    server_socket = open_listening_port(own_port);

    while (1) {
        accept_conn(server_socket, target_name, target_port);
    }

    return 0; 
}
