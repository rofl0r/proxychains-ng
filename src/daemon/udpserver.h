#ifndef SERVER_H
#define SERVER_H

#undef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>

#pragma RcB2 DEP "udpserver.c"

union sockaddr_union {
	struct sockaddr_in  v4;
	struct sockaddr_in6 v6;
};

#define SOCKADDR_UNION_AF(PTR) (PTR)->v4.sin_family

#define SOCKADDR_UNION_LENGTH(PTR) ( \
	( SOCKADDR_UNION_AF(PTR) == AF_INET  ) ? sizeof((PTR)->v4) : ( \
	( SOCKADDR_UNION_AF(PTR) == AF_INET6 ) ? sizeof((PTR)->v6) : 0 ) )

#define SOCKADDR_UNION_ADDRESS(PTR) ( \
	( SOCKADDR_UNION_AF(PTR) == AF_INET  ) ? (void*) &(PTR)->v4.sin_addr  : ( \
	( SOCKADDR_UNION_AF(PTR) == AF_INET6 ) ? (void*) &(PTR)->v6.sin6_addr : (void*) 0 ) )

#define SOCKADDR_UNION_PORT(PTR) ( \
	( SOCKADDR_UNION_AF(PTR) == AF_INET  ) ? (PTR)->v4.sin_port  : ( \
	( SOCKADDR_UNION_AF(PTR) == AF_INET6 ) ? (PTR)->v6.sin6_port : 0 ) )

struct client {
	union sockaddr_union addr;
};

struct server {
	int fd;
};

int resolve(const char *host, unsigned short port, struct addrinfo** addr);
int resolve_sa(const char *host, unsigned short port, union sockaddr_union *res);
int bindtoip(int fd, union sockaddr_union *bindaddr);

int server_waitclient(struct server *server, struct client* client, void* buf, size_t *buflen);
int server_setup(struct server *server, const char* listenip, unsigned short port);

#endif

