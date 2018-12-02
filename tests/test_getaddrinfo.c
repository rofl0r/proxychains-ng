#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>

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
		if (*hostname != '\0')
		printf("hostname: %s\n", hostname);
	}

	freeaddrinfo(result);
	return EXIT_SUCCESS;
}

int main(void) {
	int ret;
	ret = doit("www.example.com", NULL);
	ret = doit("www.example.com", "80");
	return ret;
}
