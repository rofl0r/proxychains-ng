#include <netdb.h>
#include <stdio.h>
#include <errno.h>
#include "../src/common.h"

/*
int gethostent_r( 
        struct hostent *ret, char *buf, size_t buflen,
        struct hostent **result, int *h_errnop);

Glibc2 also has reentrant versions gethostent_r(), gethostbyaddr_r(),
gethostbyname_r() and gethostbyname2_r(). 

The caller supplies a hostent structure ret which will be filled in on success, 
and a temporary work buffer buf of size buflen. 
After the call, result will point to the result on success. 
In case of an error or if no entry is found result will be NULL. 
The functions return 0 on success and a nonzero error number on failure. 
In addition to the errors returned by the nonreentrant versions of these functions, 
if buf is too small, the functions will return ERANGE, and the call should be retried 
with a larger buffer. 
The global variable h_errno is not modified, but the address of a variable in which 
to store error numbers is passed in h_errnop.
*/

void printhostent(struct hostent *hp) {
	char ipbuf[16];
	pc_stringfromipv4(hp->h_addr_list[0], ipbuf);
	printf("alias: %p, len: %d, name: %s, addrlist: %p, addrtype: %d, ip: %s\n", 
		hp->h_aliases, 
		hp->h_length,
		hp->h_name,
		hp->h_addr_list,
		hp->h_addrtype,
		ipbuf
	);
}

int main(int argc, char** argv) {
	struct hostent he_buf;
	struct hostent *he_res;
	char h_buf[1024];
	int ch_errno;
	int ret;
	do {
		ret = gethostent_r(&he_buf, h_buf, sizeof(h_buf), &he_res, &ch_errno);
		printf("ret: %d, h_errno: %d\n", ret, ch_errno);
		if(ret != 0) {
			errno = ret;
			ret = -1;
		}
		if(ret == -1) {
			perror("gethostent_r");
			break;
		}
		if(he_res) {
			printhostent(he_res);
		}
	} while (he_res);
	return 0;
}