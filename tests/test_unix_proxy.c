/*
 * test for proxies reached through a unix domain socket ("unix:" in [ProxyList]).
 *
 * start a SOCKS proxy on a unix socket, e.g.
 *     ssh -N -o StreamLocalBindMask=0177 -D /tmp/socks.sock relay
 * use a config file with
 *     [ProxyList]
 *     socks5 unix:/tmp/socks.sock
 * and run
 *     proxychains4 -f unix.conf ./test_unix_proxy example.com 80
 *
 * the socket of the application is replaced by the AF_UNIX one connected to
 * the proxy: TCP level options must still succeed, as many programs
 * (curl, python requests, ...) fail on them.
 *
 * the config must also be rejected (with a clear message) when an unix:
 * proxy is not first in the list, its path is relative or too long, or it is
 * mixed with other proxies in random_chain / round_robin_chain mode.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>

void error(const char *msg)
{
	perror(msg);
	exit(1);
}

static void set_tcp_options(int fd)
{
	int one = 1, idle = 60;
	assert(setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)) == 0);
	assert(setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one)) == 0);
	assert(setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(idle)) == 0);
}

int main(int argc, char *argv[])
{
	if (argc < 3) {
		printf("Usage: %s host port\n", argv[0]);
		return 1;
	}
	const char *hostname = argv[1];
	const int portno = atoi(argv[2]);
	char request[BUFSIZ];
	sprintf(request, "GET / HTTP/1.0\r\nHost: %s\r\n\r\n", hostname);
	int sockfd, n, sv[2];
	struct sockaddr_in serv_addr;
	struct sockaddr_storage ss;
	socklen_t sslen = sizeof(ss);
	struct hostent *server;
	char buffer[BUFSIZ];

	/* TCP options on any AF_UNIX socket are accepted under proxychains */
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0)
		error("socketpair");
	set_tcp_options(sv[0]);
	close(sv[0]);
	close(sv[1]);

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) error("ERROR opening socket");
	server = gethostbyname(hostname);
	if (server == NULL) {
		fprintf(stderr, "%s: no such host\n", hostname);
		return 1;
	}
	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	memcpy(&serv_addr.sin_addr.s_addr, server->h_addr, server->h_length);
	serv_addr.sin_port = htons(portno);
	if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
		error("connect");
	if (getsockname(sockfd, (struct sockaddr *)&ss, &sslen) < 0)
		error("getsockname");
	printf("socket family after connect: %s\n",
	       ss.ss_family == AF_UNIX ? "AF_UNIX" : ss.ss_family == AF_INET ? "AF_INET" : "other");
	set_tcp_options(sockfd);
	n = send(sockfd, request, strlen(request), 0);
	if (n < 0)
		 error("send");
	memset(buffer, 0, BUFSIZ);
	n = read(sockfd, buffer, BUFSIZ - 1);
	if (n < 0)
		 error("ERROR reading from socket");
	printf("%s\n", buffer);
	close(sockfd);
	return 0;
}
