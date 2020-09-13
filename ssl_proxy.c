/*  SSL redirector
 */
#define MAX_CONNECTION 32
#define CS_BUFFER_LEN 8192
#define SC_BUFFER_LEN 65536
#define PEM_DIR "/etc/ssl"
#define CERT_FILE "nginx-selfsigned.crt" //hardcoded
#define KEY_FILE "nginx-selfsigned.key"	//hardcoded 
#define SLEEP_US 50000

#include <stdio.h>
#include <stdarg.h>
#include <syslog.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <fcntl.h>
#include <string.h>
#include <pwd.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>

int debug_flag=0;
int info_flag=0;
int conn_timeout=0;
int max_conn=MAX_CONNECTION;
int cs_buflen=CS_BUFFER_LEN, sc_buflen=SC_BUFFER_LEN;
char *server_addr="localhost";
int server_port=8080;
char *client_addr="localhost";
int client_port=8081;
char *cert_file=PEM_DIR"/"CERT_FILE, *key_file=PEM_DIR"/"KEY_FILE;
char *cipher_list="HIGH";
char *verify_ca_file=NULL, *verify_ca_dir=NULL;


int server_socket;
SSL_CTX *server_ssl_ctx;
SSL_CTX *client_ssl_ctx; //vvi 09092020
SSL *cssl;//vvi 09092020


int client_s_family=AF_INET;
struct sockaddr *client_sa;
struct sockaddr_in client_sa_in;
struct sockaddr_un client_sa_un;
int client_sa_len;

typedef enum {cs_disconnected, 
    cs_accept, 
    cs_connecting, 
    cs_connected, 
    cs_closing
} ConnStatus;

typedef struct {
    ConnStatus stat;			// Status of the connection
    time_t event_t;			// Last event
    int server_sock;			// Server side socket id
    struct sockaddr_in server_sa;	// Server's socket address
    int server_sa_len;			// socket block's len
    SSL *ssl_conn;			// SSL connection structure pointer
    int client_sock;			// Client side socket id
    char *csbuf;			// Server side write buffer
    char *csbuf_begin;			// Server side write buffer begin ptr
    char *csbuf_end;			// Server side write buffer end ptr
    char *scbuf;			// Client side write buffer
    char *scbuf_begin;			// Client side write buffer begin ptr
    char *scbuf_end;			// Client side write buffer end ptr
} Conn;
Conn *conn=NULL;

void conn_close_client(Conn *conn);
void conn_close_server(Conn *conn);

void debug(char *format,...)
{
    if (debug_flag) {
	va_list args;
	va_start(args, format);
	vfprintf(stderr, format, args);
	putc('\n', stderr);
	va_end(args);
    }
}


void _sleep()
{
    struct timeval tv={0, SLEEP_US};
    select(0, NULL, NULL, NULL, &tv);
}

// ============================================== Server
int server_init(char *addr, int port, int maxconn)
{
    struct sockaddr_in server;
    long ipaddr;

    server_socket=socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket<0) {
	perror("socket()");
	exit(1);
    }
    server.sin_family=AF_INET;
    inet_pton(AF_INET, addr, &ipaddr);
    server.sin_addr.s_addr=ipaddr;
    server.sin_port=htons(port);
    if (bind(server_socket, (struct sockaddr *)&server, sizeof(server)) < 0) {
	perror("bind()");
	exit(1);
    }
    listen(server_socket, maxconn);
    fcntl(server_socket, F_SETFL, O_NONBLOCK);
    return server_socket;
}

void server_done(void)
{
    int ci;
    shutdown(server_socket, 2);
    _sleep();
    close(server_socket);
    for (ci=0; ci<max_conn; ci++)
	if (conn[ci].stat==cs_accept && conn[ci].stat==cs_connected) {
	    conn_close_client(&conn[ci]);
	    conn_close_server(&conn[ci]);
	}
}

// ============================================== Server SSL
static RSA *tmp_rsa_cb(SSL *ssl, int export, int key_len)
{
    static RSA *rsa=NULL; 
    debug("Generating new RSA key.. (ex=%d, kl=%d)", export, key_len);
    if (export) {
	rsa=RSA_generate_key(key_len, RSA_F4, NULL, NULL);
    } 
    return rsa;
}

static int verify_callback(int preverify_ok, X509_STORE_CTX *ctx)
{
    fprintf(stderr, "preverify: %d\n", preverify_ok);
    return preverify_ok;
}

void server_ssl_init(void)
{
    SSLeay_add_ssl_algorithms();
    SSL_load_error_strings();
    server_ssl_ctx=SSL_CTX_new(TLSv1_2_server_method());
    SSL_CTX_set_cipher_list(server_ssl_ctx, cipher_list);
    if (!SSL_CTX_set_default_verify_paths(server_ssl_ctx))  {
	fprintf(stderr, "cannot set default path\n");
	exit(1);
    }

    if (!SSL_CTX_use_certificate_chain_file(server_ssl_ctx, cert_file)) {
	fprintf(stderr,"error reading certificate by server code: %.256s\n",
		ERR_error_string(ERR_get_error(), NULL));
	exit(1);
    }
    if (!SSL_CTX_use_PrivateKey_file(server_ssl_ctx, key_file, SSL_FILETYPE_PEM)) {
	fprintf(stderr,"error reading private key by server code: %.256s\n",
		ERR_error_string(ERR_get_error(), NULL));
	exit(1);
    }
    SSL_CTX_set_tmp_rsa_callback(server_ssl_ctx, tmp_rsa_cb);

    if (verify_ca_file || verify_ca_dir) {

	SSL_CTX_load_verify_locations(server_ssl_ctx, verify_ca_file, verify_ca_dir);
	SSL_CTX_set_verify(server_ssl_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT | SSL_VERIFY_CLIENT_ONCE, verify_callback);
    }


}

// ============================================== Client SSL
void client_ssl_init(void)
{
    SSLeay_add_ssl_algorithms();
    SSL_load_error_strings();
    client_ssl_ctx=SSL_CTX_new(TLSv1_2_client_method());
    SSL_CTX_set_cipher_list(client_ssl_ctx, cipher_list);
    if (!SSL_CTX_set_default_verify_paths(client_ssl_ctx))  {
	fprintf(stderr, "cannot set default path\n");
	exit(1);
    }

    if (!SSL_CTX_use_certificate_chain_file(client_ssl_ctx, cert_file)) {
	fprintf(stderr,"error reading certificate by client code: %.256s\n",
		ERR_error_string(ERR_get_error(), NULL));
	exit(1);
    }
    if (!SSL_CTX_use_PrivateKey_file(client_ssl_ctx, key_file, SSL_FILETYPE_PEM)) {
	fprintf(stderr,"error reading private key by client code: %.256s\n",
		ERR_error_string(ERR_get_error(), NULL));
	exit(1);
    }
    SSL_CTX_set_tmp_rsa_callback(client_ssl_ctx, tmp_rsa_cb);

    if (verify_ca_file || verify_ca_dir) {

	SSL_CTX_load_verify_locations(client_ssl_ctx, verify_ca_file, verify_ca_dir);
	SSL_CTX_set_verify(client_ssl_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT | SSL_VERIFY_CLIENT_ONCE, verify_callback);
    }

}

// ============================================== Client
void client_init(char *addr, int port)
{
    if (port) { // TCP connection
	struct hostent *hp;
	client_sa_in.sin_family=AF_INET;
	hp=gethostbyname(addr);
	if (!hp) {
	    perror("gethostbyname()");
	    exit(1);
	}
	bcopy(hp->h_addr, &client_sa_in.sin_addr, hp->h_length);
	client_sa_in.sin_port=htons(port);
	client_sa=(struct sockaddr *)&client_sa_in;
	client_sa_len=sizeof(client_sa_in);
    } else { // UNIX domain socket
	client_sa_un.sun_family=AF_UNIX;
	if (addr) {
	    if (strlen(addr)>=sizeof(client_sa_un.sun_path)) {
		fprintf(stderr, "client_init(): client address too long (allowed: %d)\n",
			(int)sizeof(client_sa_un.sun_path));
		exit(1);
	    } else strcpy(client_sa_un.sun_path, addr);
	} else {
	    fprintf(stderr, "client_init(): client address missing\n");
	    exit(1);
	}
	client_sa=(struct sockaddr *)&client_sa_un;
	client_sa_len=sizeof(client_sa_un);
    }
}

// ==== Connection=================
struct sockaddr_in server_sa;

unsigned int server_sa_len;

int conn_accept(void)
{
    int i;

    int s=accept(server_socket, (struct sockaddr *)&server_sa, &server_sa_len);
    if (s<=0) return 0;
    debug("conn_accept(): Client connected");
    for (i=0; i<max_conn && conn[i].stat!=cs_disconnected; i++);
    if (i==max_conn) {
	close(s);
	return 0;
    }
    debug("accept(): sn=%d sock=%d", i, s);
    conn[i].server_sock=s;
    bcopy(&server_sa, &conn[i].server_sa, server_sa_len);
    conn[i].server_sa_len=server_sa_len;
//create SSL channel
    conn[i].ssl_conn=SSL_new(server_ssl_ctx);
    SSL_set_fd(conn[i].ssl_conn, conn[i].server_sock);
    BIO_set_nbio(SSL_get_rbio(conn[i].ssl_conn), 0);
    BIO_set_nbio(SSL_get_wbio(conn[i].ssl_conn), 0);
    fcntl(conn[i].server_sock, F_SETFL, O_NONBLOCK);
    conn[i].stat=cs_accept;
    conn[i].event_t=0;
    conn[i].scbuf_begin=conn[i].scbuf; conn[i].scbuf_end=conn[i].scbuf;
    conn[i].csbuf_begin=conn[i].csbuf; conn[i].csbuf_end=conn[i].csbuf;
    return conn[i].server_sock;
}

int conn_ssl_accept(Conn *conn)
{
    int ret=SSL_accept(conn->ssl_conn);
    debug("SSL_accept: %d, SSL_want=%d", ret, SSL_want(conn->ssl_conn));
    if (ret<=0) {
	unsigned long err=SSL_get_error(conn->ssl_conn, ret);
	if (err==SSL_ERROR_WANT_READ || err==SSL_ERROR_WANT_WRITE) {
	    return 1;
	}

	SSL_free(conn->ssl_conn);
	close(conn->server_sock);
	conn->server_sock=conn->client_sock=0;
	conn->stat=cs_disconnected;
	return -1;
    }
//---------------------------------------------------------------
    conn->client_sock=socket(client_s_family, SOCK_STREAM, 0);//
    if (conn->client_sock<0) {
	SSL_free(conn->ssl_conn);
	close(conn->server_sock);
	conn->server_sock=conn->client_sock=0;
	conn->stat=cs_disconnected;
	return -1;
    }
	
	fcntl(conn->client_sock, F_SETFL, O_NONBLOCK);
	conn->stat=cs_connecting;
    return 0;
}

void conn_close_client(Conn *conn)
{
    debug("conn_close_client(): s=%d", conn->client_sock);
    shutdown(conn->client_sock, 2);
    close(conn->client_sock);
    conn->client_sock=-1;
    if (conn->server_sock==-1) conn->stat=cs_disconnected;
}

void conn_close_server(Conn *conn)
{
    debug("conn_close_server(): s=%d", conn->server_sock);
    SSL_free(conn->ssl_conn);
    shutdown(conn->server_sock, 2);
    close(conn->server_sock);
    conn->server_sock=-1;
    if (conn->client_sock==-1) conn->stat=cs_disconnected;
}


int main(int argc, char **argv)
{
    int c, i,rez;
    char *p1, *p2;

    while ((c=getopt(argc, argv, "hdfilm:s:c:C:K:")) != EOF)
	switch (c) {
	    case 'h':
		fprintf("usage: %.256s [-d] [-s <listen address>] [-c <client address>]\n"
			"              [-C <certificate file>] [-K <key file>]\n"
			"        <listen address> = [<host>:]<port>\n"
			"        <client address> = [<host>:]<port>\n", argv[0]);
		fprintf(stderr, "       %.256s -h\n", argv[0]);
		exit(0);
	    case 'd':
		debug_flag=1;
		break;
	    case 's':
		server_port=atoi(optarg);
		p1=strtok(optarg, ":");
		p2=strtok(NULL, "");
		if (p2) {
		    server_addr=p1;
		    server_port=atoi(p2);
		} else {
		    server_addr="0.0.0.0"; server_port=atoi(p1);
		}
		break;
	    case 'c':
		p1=strtok(optarg, ":");
		p2=strtok(NULL, "");
		if (p2) {
		    if (!strcmp(p1, "unix")) {
			client_s_family=AF_UNIX;
			client_addr=p2;
			client_port=0;
		    } else {
			client_addr=p1;
			client_port=atoi(p2);
		    }
		} else {
		    client_addr="localhost"; client_port=atoi(p1);
		}
		break;
	    case 'C':
		cert_file=optarg;
		break;
	    case 'K':
		key_file=optarg;
		break;
	}
    debug(" SSL redirector started..");
    if (client_s_family==AF_INET)
	debug("Using server: family=INET host=%.256s port=%d", client_addr, client_port);
    else
	debug("Using server: family=UNIX path=%.256s", client_addr);
    server_init(server_addr, server_port, max_conn);
    server_ssl_init();
    client_init(client_addr, client_port);
    //-----------insert client ssl vvi 09.09.2020
    client_ssl_init(); //ad vvi 10.09.2020

    conn=malloc(max_conn*sizeof(Conn));
    bzero(conn, max_conn*sizeof(Conn));
    for (i=0; i<max_conn; i++) {
	Conn *c=&conn[i];
	c->scbuf=malloc(sc_buflen);
	c->scbuf_begin=c->scbuf; c->scbuf_end=c->scbuf;
	c->csbuf=malloc(cs_buflen);
	c->csbuf_begin=c->csbuf; c->csbuf_end=c->csbuf;
    }

    while (1) {
	int eventsum=0, ci;
	// Check for incoming connections
	if ((i=conn_accept())>0) {
	    debug("Client connected");
	    eventsum=1;
	}
	for (ci=0; ci<max_conn; ci++) {
	    Conn *cn=&conn[ci];
	    int event=0, l;
	    time_t tm;
	    switch (cn->stat) {
		case cs_accept:
		    i=conn_ssl_accept(cn);
		    event|=(i==0);
		    break;
		case cs_connecting:
		    if (connect(cn->client_sock, client_sa, client_sa_len)<0) { //connect to server fail
			if (errno==EINPROGRESS) break;
			close(cn->client_sock);
			SSL_free(cn->ssl_conn);
			close(cn->server_sock);
			cn->stat=cs_disconnected;
		    } else { 
			
//-----------------------------create SSL channel
		cssl=SSL_new(client_ssl_ctx);
		SSL_set_fd(cssl, cn->client_sock);
		 BIO_set_nbio(SSL_get_rbio(cssl), 0);
		 BIO_set_nbio(SSL_get_wbio(cssl), 0);

		rez = SSL_connect(cssl);
			if (rez > 0) {
				 debug("ssl_conn_to_server_established: s=%d", cn->client_sock);//vvi 09092020
				     }
//-------------------------------------------------------------------	
			struct sockaddr_in client_addr;
			unsigned int client_addr_len=sizeof(client_addr);
			X509 *cert;
			X509_NAME *xn=NULL;
			char peer_cn[256]="";
			
			getpeername(cn->server_sock,
				(struct sockaddr *)&client_addr,
				&client_addr_len);
			cert=SSL_get_peer_certificate(cn->ssl_conn);
			if (cert) {
			    xn=X509_get_subject_name(cert);
			    X509_NAME_get_text_by_NID(xn, NID_commonName, peer_cn, 256);
			}
			if (info_flag) {
			    cn->csbuf_end+=snprintf(cn->csbuf_begin, cs_buflen,
				    "#@ip=%s port=%d%s%s%s\r\n",
				    inet_ntoa(client_addr.sin_addr),
				    htons(client_addr.sin_port), xn?" cn='":"", peer_cn, xn?"'":"");
			    debug("INFO: %p %d %s", cn, cn->server_sock, cn->csbuf);
			}

			cn->stat=cs_connected;
		    }
		    break;
		case cs_connected:
		    if ((l=cs_buflen-(cn->csbuf_end-cn->csbuf))) {
			i=SSL_read(cn->ssl_conn, cn->csbuf_end, l);
			if (i<=0) { // Error, or shutdown
			    if (errno!=EAGAIN) {

				cn->stat=cs_closing; event=1;
			    }
			} else cn->csbuf_end+=i;
		    }
		case cs_closing:
		    // Send buffered data to server
		    if ((l=cn->csbuf_end-cn->csbuf_begin)>0) {
			i=SSL_write(cssl, cn->csbuf_begin, l); //by vvi 09092020
			if (debug_flag) write(2, cn->csbuf_begin, l);
			if (i>=0) {
			    cn->csbuf_begin+=i;
			} else {
			    if (errno!=EAGAIN) {
				cn->csbuf_begin=cn->csbuf_end=cn->csbuf;
				cn->stat=cs_closing;
			    }
			}
			if (cn->csbuf_begin==cn->csbuf_end) {
			    cn->csbuf_begin=cn->csbuf_end=cn->csbuf;
			}
		    }
		    if (cn->stat==cs_closing && cn->csbuf_end==cn->csbuf_begin) conn_close_client(cn);
		default:;
	    }
	    if (cn->stat==cs_connected || cn->stat==cs_closing) {
		if ((l=sc_buflen-(cn->scbuf_end-cn->scbuf)) && cn->client_sock>=0) {
			i=SSL_read(cssl, cn->scbuf_end, l); //by vvi 09092020
		    if (!i) { // End of connection
			cn->stat=cs_closing; event=1;
		    } else if (i<0) { // Error
			if (errno!=EAGAIN) {
			    cn->stat=cs_closing; event=1;
			}
		    } else cn->scbuf_end+=i;
		}
		// Send buffered data to client
		if ((l=cn->scbuf_end-cn->scbuf_begin)>0 && cn->server_sock>=0) {
		    i=SSL_write(cn->ssl_conn, cn->scbuf_begin, l);
		    if (i>0) debug("transfer: buf=%d, b=%d, l=%d, i=%d", cn->scbuf,
			    cn->scbuf_begin, l, i);
		    if (i>=0) {
			cn->scbuf_begin+=i; event=1;
		    } else if (errno!=EAGAIN) {
			cn->scbuf_begin=cn->scbuf_end=cn->scbuf;
			event=1;
		    }
		    if (cn->scbuf_begin==cn->scbuf_end) {
			cn->scbuf_begin=cn->scbuf_end=cn->scbuf;
		    }
		}
		if (cn->stat==cs_closing && cn->scbuf_end==cn->scbuf_begin) conn_close_server(cn);
		tm=time(NULL);
		if (event) {
		    cn->event_t=tm;
		}
		if (conn_timeout && cn->stat!=cs_disconnected && cn->event_t && tm-cn->event_t>conn_timeout) {
		    cn->stat=cs_closing; event=1;
		}
	    }
	    eventsum+=event;
	}
	if (!eventsum) _sleep();
    }
    return 0;
}
