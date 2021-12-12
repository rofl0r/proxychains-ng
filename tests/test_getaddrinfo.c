#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <assert.h>
#include <string.h>

#ifndef   NI_MAXHOST
#define   NI_MAXHOST 1025
#endif

static int doit(const char* host, const char* service) {
	struct addrinfo *result;
	struct addrinfo *res;
	int error;

	/* resolve the domain name into a list of addresses */
	error = getaddrinfo(host, service, NULL, &result);
	if (error != 0)
	{
		fprintf(stderr, "error in getaddrinfo: %s\n", gai_strerror(error));
		return EXIT_FAILURE;
	}

	/* loop over all returned results and do inverse lookup */
	for (res = result; res != NULL; res = res->ai_next)
	{
		char hostname[NI_MAXHOST] = "";

		error = getnameinfo(res->ai_addr, res->ai_addrlen, hostname, NI_MAXHOST, NULL, 0, 0);
		if (error != 0)
		{
		fprintf(stderr, "error in getnameinfo: %s\n", gai_strerror(error));
		continue;
		}
		int port = 0;
		if(res->ai_family == AF_INET) port = ((struct sockaddr_in*)res->ai_addr)->sin_port;
		else if(res->ai_family == AF_INET6) port = ((struct sockaddr_in6*)res->ai_addr)->sin6_port;
		port = ntohs(port);
		printf("hostname: %s, port: %d\n", hostname, port);
	}

	freeaddrinfo(result);
	return EXIT_SUCCESS;
}

/* reproduce use of getaddrinfo as used by nmap 7.91's canonicalize_address */
int canonicalize_address(struct sockaddr_storage *ss, struct sockaddr_storage *output) {
	char canonical_ip_string[NI_MAXHOST];
	struct addrinfo *ai;
	int rc;
	/* Convert address to string. */
	rc = getnameinfo((struct sockaddr *) ss, sizeof(*ss),
		canonical_ip_string, sizeof(canonical_ip_string), NULL, 0, NI_NUMERICHOST);
	assert(rc == 0);
	struct addrinfo hints = {
		.ai_family = ss->ss_family,
		.ai_socktype = SOCK_DGRAM,
		.ai_flags = AI_NUMERICHOST,
	};
	rc = getaddrinfo(canonical_ip_string, NULL, &hints, &ai);
	if (rc != 0 || ai == NULL)
		return -1;
	assert(ai->ai_addrlen > 0 && ai->ai_addrlen <= (int) sizeof(*output));
	memcpy(output, ai->ai_addr, ai->ai_addrlen);
	freeaddrinfo(ai);
	return 0;
}

int main(void) {
	int ret;
	ret = doit("www.example.com", NULL);
	ret = doit("www.example.com", "80");
	struct sockaddr_storage o, ss = {.ss_family = PF_INET};
	struct sockaddr_in *v4 = &ss;
	struct sockaddr_in6 *v6 = &ss;
	memcpy(&v4->sin_addr, "\x7f\0\0\1", 4);
	ret = canonicalize_address(&ss, &o);
	assert (ret == 0);
	ss.ss_family = PF_INET6;
	memcpy(&v6->sin6_addr, "\0\0\0\0" "\0\0\0\0" "\0\0\0\0""\0\0\0\1", 16);
	ret = canonicalize_address(&ss, &o);
	assert (ret == 0);
	return ret;
}
