#include <sys/socket.h>

extern int pc_getnameinfo(const void *sa, socklen_t salen, 
                   char *host, socklen_t hostlen, char *serv, 
                   socklen_t servlen, int flags);


int getnameinfo(const void *sa, socklen_t salen, 
                   char *host, socklen_t hostlen, char *serv, 
                   socklen_t servlen, int flags) {
	return pc_getnameinfo(sa, salen, host, hostlen, serv, servlen, flags);
}

