#include <stdio.h>
#include <netdb.h>
#include "../src/common.c"

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
int main(int argc, char**argv) {
	struct hostent* ret;
	if(argc == 1) return 1;
	ret = gethostbyname(argv[1]);
	if(ret) printhostent(ret);
	return 0;
}
