
#ifdef DEBUG
# include "core.h"
# include "common.h"
# include "debug.h"
#include <arpa/inet.h>

void dump_proxy_chain(proxy_data *pchain, unsigned int count) {
	char ip_buf[INET6_ADDRSTRLEN];
	for (; count; pchain++, count--) {
		if(!inet_ntop(pchain->ip.is_v6?AF_INET6:AF_INET,pchain->ip.addr.v6,ip_buf,sizeof ip_buf)) {
			proxychains_write_log(LOG_PREFIX "error: ip address conversion failed\n");
			continue;
		}
		PDEBUG("[%s] %s %s:%d", proxy_state_strmap[pchain->ps],
		       proxy_type_strmap[pchain->pt], 
		       ip_buf, htons(pchain->port));
		if (*pchain->user || *pchain->pass) {
			PSTDERR(" [u=%s,p=%s]", pchain->user, pchain->pass);
		}
		PSTDERR("\n");
	}
}

void dump_buffer(unsigned char * data, size_t len){
	printf("buffer_dump[");
	for(int i=0; i<len; i++){
		printf("%d ", *(data+i));
	}
	printf("]\n");
}

#else

// Do not allow this translation unit to end up empty
// for non-DEBUG builds, to satisfy ISO C standards.
typedef int __appease_iso_compilers__;

#endif
