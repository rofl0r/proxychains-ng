#ifndef RDNS_H
#define RDNS_H

#include <unistd.h>
#include <netinet/in.h>
#include "ip_type.h"
#include "remotedns.h"

enum dns_lookup_flavor {
	DNSLF_LIBC = 0,
	DNSLF_FORKEXEC,

	DNSLF_RDNS_START,
	DNSLF_RDNS_THREAD = DNSLF_RDNS_START,
	DNSLF_RDNS_DAEMON,
};

void rdns_init(enum dns_lookup_flavor flavor);
void rdns_set_daemon(struct sockaddr_in* addr);
const char *rdns_resolver_string(enum dns_lookup_flavor flavor);
size_t rdns_get_host_for_ip(ip_type4 ip, char* readbuf);
ip_type4 rdns_get_ip_for_host(char* host, size_t len);

//enum dns_lookup_flavor rdns_get_flavor(void);
#define rdns_get_flavor() proxychains_resolver
extern enum dns_lookup_flavor proxychains_resolver;

#endif
