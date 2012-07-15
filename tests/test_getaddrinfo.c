#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
 
#ifndef   NI_MAXHOST
#define   NI_MAXHOST 1025
#endif
 
int main(void) {
	struct addrinfo *result;
	struct addrinfo *res;
	int error;
	
	/* resolve the domain name into a list of addresses */
	error = getaddrinfo("www.example.com", NULL, NULL, &result);
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
