#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>

static void v4_to_v6(const struct in_addr *v4, struct in6_addr *v6) {
	memset(v6, 0, sizeof(*v6));
	v6->s6_addr[10]=0xff;
	v6->s6_addr[11]=0xff;
	memcpy(&v6->s6_addr[12], &v4->s_addr, 4);
}

int main(void) {
	struct addrinfo *result;
	struct addrinfo *res;
	const struct addrinfo hints = { .ai_family = AF_INET };
	int error, sock;

	/* resolve the domain name into a list of addresses */
	error = getaddrinfo("www.example.com", NULL, &hints, &result);
	if (error != 0)	{
		fprintf(stderr, "error in getaddrinfo: %s\n", gai_strerror(error));
		return EXIT_FAILURE;
	}
	if((sock=socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
		perror("socket");
		return EXIT_FAILURE;
	}
	struct sockaddr_in6 a = { .sin6_family = AF_INET6,
	                          .sin6_port = htons(80) };
	v4_to_v6(&((struct sockaddr_in *)result->ai_addr)->sin_addr, &a.sin6_addr);
	freeaddrinfo(result);

	if((error = connect(sock, (struct sockaddr *)&a, sizeof(a))) == -1) {
		perror("connect");
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
