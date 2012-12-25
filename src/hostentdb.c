#include <stdint.h>
#include <string.h>
#include <netdb.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "ip_type.h"
#include "hash.h"
#include "stringdump.h"
#include "hostentdb.h"
#include "common.h"
#include "debug.h"

#define STEP 16
static void hdb_add(struct hostent_list* hl, char* host, ip_type ip) {
	if(hl->count +1 > hl->capa) {
		void * nu = realloc(hl->entries, (hl->capa + STEP) * sizeof(struct hostent_entry));
		if(!nu) return;
		hl->entries = nu;
		hl->capa += STEP;
	}
	struct hostent_entry *h = &hl->entries[hl->count];
	h->hash = dalias_hash(host);
	h->ip.as_int = ip.as_int;
	h->str = dumpstring(host, strlen(host) + 1); 
	if(h->str) hl->count++;
}

static void hdb_fill(struct hostent_list *hl) {
#ifndef IS_BSD
	struct hostent* hp;
	while((hp = gethostent()))
		if(hp->h_addrtype == AF_INET && hp->h_length == sizeof(in_addr_t)) {
			hdb_add(hl, hp->h_name, (ip_type) { .as_int = *((in_addr_t*)(hp->h_addr_list[0])) });
		}
#else
	/* FreeBSD hangs on gethostent(). since this feature is not crucial, we just do nothing */
	(void) hl;
#endif
}

void hdb_init(struct hostent_list *hl) {
	memset(hl, 0, sizeof *hl);
	hdb_fill(hl);
}

ip_type hdb_get(struct hostent_list *hl, char* host) {
	size_t i;
	PFUNC();
	uint32_t hash = dalias_hash(host);
	for(i = 0; i < hl->count; i++) {
		if(hl->entries[i].hash == hash && !strcmp(hl->entries[i].str, host)) {
		#ifdef DEBUG
			char ipbuf[16];
			pc_stringfromipv4(hl->entries[i].ip.octet, ipbuf);
			PDEBUG("got ip %s for hostent entry %s\n", ipbuf, host);
		#endif
			return hl->entries[i].ip;
		}
	}
	return ip_type_invalid;
}
