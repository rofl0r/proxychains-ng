#include "../src/core.h"
#include "../src/common.h"
#include <stdio.h>

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
	struct gethostbyname_data data;
	if(argc == 1) return 1;
	ret = proxy_gethostbyname(argv[1], &data);
	if(ret) printhostent(ret);
	return 0;
}