#ifndef HOSTENTDB_H
#define HOSTENTDB_H

#include "ip_type.h"
#include <unistd.h>

struct hostent_entry {
	uint32_t hash;
	ip_type ip;
	char* str;
};

struct hostent_list {
	size_t count;
	size_t capa;
	struct hostent_entry *entries;
};

void hdb_init(struct hostent_list *hl);
ip_type hdb_get(struct hostent_list *hl, char* host);

//RcB: DEP "hostendb.c"
#endif
