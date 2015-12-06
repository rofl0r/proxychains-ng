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

#define ASSERT(X) { if(!(X)) printf("ASSERTION FAILED: %s @%s:%d\n", # X, __FILE__, __LINE__); }
#define CLR() { hbuf[0] = 0; sbuf[0] = 0; }

int main() {
	struct sockaddr_in a = {0}, *sa = &a;
	char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];
	a.sin_port = htons(80);
	memcpy(  &a.sin_addr   , (char[]) {127,0,0,1}, 4);

	int ret;

	if ((ret = getnameinfo((void*)sa, 0, hbuf, sizeof(hbuf), sbuf,
	    sizeof(sbuf), NI_NUMERICHOST | NI_NUMERICSERV)) == 0)
		printf("host=%s, serv=%s\n", hbuf, sbuf);
	else
		printf("%s\n", gai_strerror(ret));

	ASSERT(ret == EAI_FAMILY);
	CLR();

	if ((ret = getnameinfo((void*)sa, sizeof a, hbuf, sizeof(hbuf), sbuf,
	    sizeof(sbuf), NI_NUMERICHOST | NI_NUMERICSERV)) == 0)
		printf("host=%s, serv=%s\n", hbuf, sbuf);
	else
		printf("%s\n", gai_strerror(ret));

	ASSERT(ret == EAI_FAMILY);
	CLR();

	SOCKFAMILY(a) = AF_INET;

	if ((ret = getnameinfo((void*)sa, sizeof a, hbuf, 1, sbuf,
	    sizeof(sbuf), NI_NUMERICHOST | NI_NUMERICSERV)) == 0)
		printf("host=%s, serv=%s\n", hbuf, sbuf);
	else
		printf("%s\n", gai_strerror(ret));

	ASSERT(ret == EAI_OVERFLOW);
	CLR();

	if ((ret = getnameinfo((void*)sa, sizeof a, hbuf, 0, sbuf,
	    1, NI_NUMERICHOST | NI_NUMERICSERV)) == 0)
		printf("host=%s, serv=%s\n", hbuf, sbuf);
	else
		printf("%s\n", gai_strerror(ret));

	ASSERT(ret == EAI_OVERFLOW);
	CLR();

	if ((ret = getnameinfo((void*)sa, sizeof(a) - 1, hbuf, 0, sbuf,
	    sizeof(sbuf), NI_NUMERICHOST | NI_NUMERICSERV)) == 0)
		printf("host=%s, serv=%s\n", hbuf, sbuf);
	else
		printf("%s\n", gai_strerror(ret));

	ASSERT(ret == EAI_FAMILY);
	CLR();

	if ((ret = getnameinfo((void*)sa, sizeof a, hbuf, 0, sbuf,
	    sizeof(sbuf), NI_NUMERICHOST | NI_NUMERICSERV)) == 0)
		printf("host=%s, serv=%s\n", hbuf, sbuf);
	else
		printf("%s\n", gai_strerror(ret));

	ASSERT(ret == 0 && !strcmp("80", sbuf));
	CLR();

	if ((ret = getnameinfo((void*)sa, sizeof a, hbuf, sizeof hbuf, sbuf,
	    0, NI_NUMERICHOST | NI_NUMERICSERV)) == 0)
		printf("host=%s, serv=%s\n", hbuf, sbuf);
	else
		printf("%s\n", gai_strerror(ret));

	ASSERT(ret == 0 && !strcmp("127.0.0.1",hbuf));
	CLR();


	if ((ret = getnameinfo((void*)sa, sizeof a, hbuf, sizeof(hbuf), sbuf,
	    sizeof(sbuf), NI_NUMERICHOST | NI_NUMERICSERV)) == 0)
		printf("host=%s, serv=%s\n", hbuf, sbuf);
	else
		printf("%s\n", gai_strerror(ret));

	ASSERT(ret == 0 && !strcmp("127.0.0.1",hbuf) && !strcmp("80", sbuf));
	CLR();

	struct sockaddr_in6 b = {0}, *sb = &b;
	b.sin6_port = htons(8080);
	b.sin6_family = AF_INET6;

	memcpy(&b.sin6_addr,"\0\0\0\0\0\0\0\0\0\0\xff\xff\xc0\xa8\1\2", 16);

	if ((ret = getnameinfo((void*)sb, sizeof b, hbuf, sizeof(hbuf), sbuf,
	    sizeof(sbuf), NI_NUMERICHOST | NI_NUMERICSERV)) == 0)
		printf("host=%s, serv=%s\n", hbuf, sbuf);
	else
		printf("%s\n", gai_strerror(ret));

	ASSERT(ret == 0 && !strcmp("192.168.1.2",hbuf) && !strcmp("8080", sbuf));
	CLR();

	b.sin6_scope_id = 3;
	memcpy(&b.sin6_addr,"\0\0\xaa\0\0\0\0\0\0\0\0\xff\xc0\xa8\1\2", 16);

	if ((ret = getnameinfo((void*)sb, sizeof b, hbuf, sizeof(hbuf), sbuf,
	    sizeof(sbuf), NI_NUMERICHOST | NI_NUMERICSERV | NI_NUMERICSCOPE)) == 0)
		printf("host=%s, serv=%s\n", hbuf, sbuf);
	else
		printf("%s\n", gai_strerror(ret));

	ASSERT(ret == 0);

	return 0;
}
