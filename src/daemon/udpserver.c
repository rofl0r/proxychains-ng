#include "udpserver.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int resolve(const char *host, unsigned short port, struct addrinfo** addr) {
	struct addrinfo hints = {
		.ai_family = AF_UNSPEC,
		.ai_socktype = SOCK_STREAM,
		.ai_flags = AI_PASSIVE,
	};
	char port_buf[8];
	snprintf(port_buf, sizeof port_buf, "%u", port);
	return getaddrinfo(host, port_buf, &hints, addr);
}

int resolve_sa(const char *host, unsigned short port, union sockaddr_union *res) {
	struct addrinfo *ainfo = 0;
	int ret;
	SOCKADDR_UNION_AF(res) = AF_UNSPEC;
	if((ret = resolve(host, port, &ainfo))) return ret;
	memcpy(res, ainfo->ai_addr, ainfo->ai_addrlen);
	freeaddrinfo(ainfo);
	return 0;
}

int bindtoip(int fd, union sockaddr_union *bindaddr) {
	socklen_t sz = SOCKADDR_UNION_LENGTH(bindaddr);
	if(sz)
		return bind(fd, (struct sockaddr*) bindaddr, sz);
	return 0;
}

int server_waitclient(struct server *server, struct client* client, void* buf, size_t *buflen) {
	socklen_t clen = sizeof client->addr;
	ssize_t ret = recvfrom(server->fd, buf, *buflen, 0, (void*)&client->addr, &clen);
	if(ret >= 0) {
		*buflen = ret;
		return 0;
	}
	return ret;
}

int server_setup(struct server *server, const char* listenip, unsigned short port) {
	struct addrinfo *ainfo = 0;
	if(resolve(listenip, port, &ainfo)) return -1;
	struct addrinfo* p;
	int listenfd = -1;
	for(p = ainfo; p; p = p->ai_next) {
		if((listenfd = socket(p->ai_family, SOCK_DGRAM, 0)) < 0)
			continue;
		int yes = 1;
		setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));
		if(bind(listenfd, p->ai_addr, p->ai_addrlen) < 0) {
			close(listenfd);
			listenfd = -1;
			continue;
		}
		break;
	}
	freeaddrinfo(ainfo);
	if(listenfd < 0) return -2;
	server->fd = listenfd;
	return 0;
}
