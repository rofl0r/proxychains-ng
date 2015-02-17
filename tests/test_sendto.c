#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#ifndef MSG_FASTOPEN
#   define MSG_FASTOPEN 0x20000000
#endif

void error(const char *msg)
{
	perror(msg);
	exit(1);
}

int main(int argc, char *argv[])
{
	if (argc < 4) {
		printf("Usage: %s host port method(connect or sendto)\n", argv[0]);
		return 1;
	}
	const char *hostname = argv[1];
	const int portno = atoi(argv[2]);
	const char *method = argv[3];
	char request[BUFSIZ];
	sprintf(request, "GET / HTTP/1.0\r\nHost: %s\r\n\r\n", hostname);
	int sockfd, n;
	struct sockaddr_in serv_addr;
	struct hostent *server;

	char buffer[BUFSIZ];
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
	if (!strcmp(method, "connect")) {
	  if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
		  error("connect");
	  n = send(sockfd, request, strlen(request), 0);
	} else if (!strcmp(method, "sendto")) {
	  n = sendto(sockfd, request, strlen(request), MSG_FASTOPEN, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
	} else {
	  printf("Unknown method %s\n", method);
	  return 1;
	}
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
