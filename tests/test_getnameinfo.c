#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define     satosin(x)      ((struct sockaddr_in *) &(x))
#define     SOCKADDR(x)     (satosin(x)->sin_addr.s_addr)
#define     SOCKADDR_2(x)     (satosin(x)->sin_addr)
#define     SOCKPORT(x)     (satosin(x)->sin_port)
#define     SOCKFAMILY(x)     (satosin(x)->sin_family)

int main() {
	struct sockaddr a = {0}, *sa = &a;
	char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];
	SOCKPORT(a) = htons(80);
	memcpy(  &( (struct sockaddr_in*) sa ) ->sin_addr   , (char[]) {127,0,0,1}, 4);

	int ret;

	if ((ret = getnameinfo(sa, 0, hbuf, sizeof(hbuf), sbuf,
	    sizeof(sbuf), NI_NUMERICHOST | NI_NUMERICSERV)) == 0)
		printf("host=%s, serv=%s\n", hbuf, sbuf);
	else
		printf("%s\n", gai_strerror(ret));

	assert(ret == EAI_FAMILY);

	if ((ret = getnameinfo(sa, sizeof a, hbuf, sizeof(hbuf), sbuf,
	    sizeof(sbuf), NI_NUMERICHOST | NI_NUMERICSERV)) == 0)
		printf("host=%s, serv=%s\n", hbuf, sbuf);
	else
		printf("%s\n", gai_strerror(ret));

	assert(ret == EAI_FAMILY);

	SOCKFAMILY(a) = AF_INET;

	if ((ret = getnameinfo(sa, sizeof a, hbuf, 1, sbuf,
	    sizeof(sbuf), NI_NUMERICHOST | NI_NUMERICSERV)) == 0)
		printf("host=%s, serv=%s\n", hbuf, sbuf);
	else
		printf("%s\n", gai_strerror(ret));

	assert(ret == EAI_OVERFLOW);

	if ((ret = getnameinfo(sa, sizeof a, hbuf, 0, sbuf,
	    1, NI_NUMERICHOST | NI_NUMERICSERV)) == 0)
		printf("host=%s, serv=%s\n", hbuf, sbuf);
	else
		printf("%s\n", gai_strerror(ret));

	assert(ret == EAI_OVERFLOW);

	if ((ret = getnameinfo(sa, sizeof a, hbuf, 0, sbuf,
	    sizeof(sbuf), NI_NUMERICHOST | NI_NUMERICSERV)) == 0)
		printf("host=%s, serv=%s\n", hbuf, sbuf);
	else
		printf("%s\n", gai_strerror(ret));

	assert(ret == 0);

	if ((ret = getnameinfo(sa, sizeof a, hbuf, sizeof hbuf, sbuf,
	    0, NI_NUMERICHOST | NI_NUMERICSERV)) == 0)
		printf("host=%s, serv=%s\n", hbuf, sbuf);
	else
		printf("%s\n", gai_strerror(ret));

	assert(ret == 0);


	if ((ret = getnameinfo(sa, sizeof a, hbuf, sizeof(hbuf), sbuf,
	    sizeof(sbuf), NI_NUMERICHOST | NI_NUMERICSERV)) == 0)
		printf("host=%s, serv=%s\n", hbuf, sbuf);
	else
		printf("%s\n", gai_strerror(ret));

	assert(ret == 0);

		
	return 0;
}
