/***************************************************************************
                          libproxychains.c  -  description
                             -------------------
    begin                : Tue May 14 2002
    copyright          :  netcreature (C) 2002
    email                 : netcreature@users.sourceforge.net
 ***************************************************************************/
 /*     GPL */
/***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 ***************************************************************************/

#undef _GNU_SOURCE
#define _GNU_SOURCE

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <netdb.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <pthread.h>


#include "core.h"
#include "common.h"

#define     satosin(x)      ((struct sockaddr_in *) &(x))
#define     SOCKADDR(x)     (satosin(x)->sin_addr.s_addr)
#define     SOCKADDR_2(x)     (satosin(x)->sin_addr)
#define     SOCKPORT(x)     (satosin(x)->sin_port)
#define     SOCKFAMILY(x)     (satosin(x)->sin_family)

close_t true_close;
connect_t true_connect;
gethostbyname_t true_gethostbyname;
getaddrinfo_t true_getaddrinfo;
freeaddrinfo_t true_freeaddrinfo;
getnameinfo_t true_getnameinfo;
gethostbyaddr_t true_gethostbyaddr;

int proxychains_quiet_mode = 0;
int proxychains_resolver = 0;

proxy_chain_list *proxychains_chain_list = NULL;

pthread_once_t init_once = PTHREAD_ONCE_INIT;

static int init_l = 0;

static inline void get_chain_data(proxy_chain_list *pc_list);
static inline int get_chain_type(char *buff, chain_type *ct);
int proxy_chain_list_load(proxy_chain_list *pc_list);
int proxy_chain_load_pdata(proxy_chain *pc, proxy_data *pd_list, int count);
proxy_chain* proxy_chain_list_set_selected(proxy_chain_list *pc_list, const char *chain_name);

static void* load_sym(char* symname, void* proxyfunc) {

	void *funcptr = dlsym(RTLD_NEXT, symname);
	
	if(!funcptr) {
		fprintf(stderr, "Cannot load symbol '%s' %s\n", symname, dlerror());
		exit(1);
	} else {
		PDEBUG("loaded symbol '%s'" " real addr %p  wrapped addr %p\n", symname, funcptr, proxyfunc);
	}
	if(funcptr == proxyfunc) {
		PDEBUG("circular reference detected, aborting!\n");
		abort();
	}
	return funcptr;
}

#define INIT() init_lib_wrapper(__FUNCTION__)

#define SETUP_SYM(X) do { true_ ## X = load_sym( # X, X ); } while(0)

#include "shm.h"
#include "allocator_thread.h"
#include "stringdump.h"

static void do_init(void) {
	srand(time(NULL));
	dumpstring_init(); // global string garbage can
	core_initialize();
	at_init();
	
	proxy_chain_list_load(proxychains_chain_list);

	proxychains_write_log(LOG_PREFIX "DLL init\n");
	
	SETUP_SYM(connect);
	SETUP_SYM(gethostbyname);
	SETUP_SYM(getaddrinfo);
	SETUP_SYM(freeaddrinfo);
	SETUP_SYM(gethostbyaddr);
	SETUP_SYM(getnameinfo);
	SETUP_SYM(close);
	
	init_l = 1;
}

#if 0
/* FIXME this is currently unused.
 * it is not strictly needed.
 * maybe let it be called by a gcc destructor, if that doesnt
 * have negative consequences (e.g. when a child calles exit) */
static void unload(void) {
	at_close();
	core_unload();
}
#endif

static void init_lib_wrapper(const char* caller) {
#ifndef DEBUG
	(void) caller;
#endif
	if(!init_l) PDEBUG("%s called from %s\n", __FUNCTION__,  caller);
	pthread_once(&init_once, do_init);
}

/* if we use gcc >= 3, we can instruct the dynamic loader 
 * to call init_lib at link time. otherwise it gets loaded
 * lazily, which has the disadvantage that there's a potential
 * race condition if 2 threads call it before init_l is set 
 * and PTHREAD support was disabled */
#if __GNUC__ > 2
__attribute__((constructor))
static void gcc_init(void) {
	INIT();
}
#endif

/* get configuration from config file */
static void get_chain_data(proxy_chain_list *pc_list) {
	static int got_chain_data = 0;
	int count = 0, port_n = 0, list = 0;
	char buff[1024], type[1024], host[1024], label[1024];
	char *env;
	char local_in_addr_port[32];
	char local_in_addr[32], local_in_port[32], local_netmask[32];
	FILE *file = NULL;
	proxy_chain *pc_curr = NULL;
	proxy_data pd_list[MAX_CHAIN];

	if(got_chain_data)
		return;
	
	env = get_config_path(getenv(PROXYCHAINS_CONF_FILE_ENV_VAR), buff, sizeof(buff));
	if( ( file = fopen(env, "r") ) == NULL )
	{
	        perror("couldnt read configuration file");
        	exit(1);
	}

	env = getenv(PROXYCHAINS_QUIET_MODE_ENV_VAR);
	if(env && *env == '1')
		proxychains_quiet_mode = 1;

	while(fgets(buff, sizeof(buff), file)) {
		if(buff[0] != '\n' && buff[strspn(buff, " ")] != '#') {
			/* proxylist has to come last */
			if(list && (buff[0] != '[')) {
				if(count >= MAX_CHAIN)
					break;
				
				memset(&pd_list[count], 0, sizeof(proxy_data));

				pd_list[count].ps = PLAY_STATE;
				port_n = 0;
				
				if(strstr(buff, "tcp_read_time_out")) {
					sscanf(buff, "%s %d", label, &pc_curr->tcp_read_time_out);
				} else if(strstr(buff, "tcp_connect_time_out")) {
					sscanf(buff, "%s %d", label, &pc_curr->tcp_connect_time_out);
				} else if(strstr(buff, "chain_len")) {
					char *pc;
					int len = 1;
					pc = strchr(buff, '=');
					if ((pc=strchr(buff, '=')) == NULL) {
						fprintf(stderr, "Warning: chain_len must use '='\n");
					} else
						len = atoi(++pc);
					pc_curr->max_chain = len;
				} else if(!get_chain_type(buff, &pc_curr->ct)) {
					;
				} else {
					pd_list[count].user[0] = pd_list[count].pass[0] = '\0';
					sscanf(buff, "%s %s %d %s %s", type, host, &port_n, pd_list[count].user, pd_list[count].pass);

					in_addr_t host_ip = inet_addr(host);
					if(host_ip == INADDR_NONE) {
						fprintf(stderr, "proxy %s has invalid value or is not numeric\n", host);
						exit(1);
					}
					pd_list[count].ip.as_int = (uint32_t) host_ip;
					pd_list[count].port = htons((unsigned short) port_n);

					if(!strcmp(type, "http")) {
						pd_list[count].pt = HTTP_TYPE;
					} else if(!strcmp(type, "socks4")) {
						pd_list[count].pt = SOCKS4_TYPE;
					} else if(!strcmp(type, "socks5")) {
						pd_list[count].pt = SOCKS5_TYPE;
					} else
						continue;

					if(pd_list[count].ip.as_int && port_n && pd_list[count].ip.as_int != (uint32_t) - 1)
						count++;
				}
			} else {
				char *s1, *s2;
				if((s1=(strstr(buff, "["))+1) && (s1 < (s2=strstr(buff, "]")))) {
					/* If have a previous chain stored in the temp chain, copy
					   to global lists. */
					if (count) {
						proxy_chain_load_pdata(pc_curr, pd_list, count);
						count = 0;
					}
					
					PDEBUG("Parsing chain: %s\n", buff);
					if (pc_list->count >= MAX_CHAIN_LISTS) {
						proxychains_write_log(LOG_PREFIX "Warning more than %d lists defined in configfile, skipping any more list definitions.\n", MAX_CHAIN_LISTS);
						continue;
					}
					
					/* Create new proxy list */
					pc_curr = pc_list->pc[pc_list->count++] = (proxy_chain*)malloc(sizeof(proxy_chain));
					if (pc_curr ==  NULL) {
						proxychains_write_log(LOG_PREFIX "Error failed to allocate proxy chain object\n");
						exit(1);
					}
					pc_curr->ct = DYNAMIC_TYPE;
					pc_curr->count = 0;
					pc_curr->offset = 0;
					pc_curr->max_chain = 1;
					pc_curr->tcp_read_time_out = pc_list->tcp_read_time_out;
					pc_curr->tcp_connect_time_out = pc_list->tcp_connect_time_out;
					
					pc_curr->name = (char*)malloc(sizeof(char)*(s2-s1));
					if (pc_curr->name ==  NULL) {
						proxychains_write_log(LOG_PREFIX "Error failed to allocate proxy chain name string\n");
						exit(1);
					}
					strncpy(pc_curr->name, s1, s2-s1);
					
					list = 1;
				} else if(!get_chain_type(buff, &pc_list->ct)) {
					;
				} else if(strstr(buff, "tcp_read_time_out")) {
					sscanf(buff, "%s %d", label, &pc_list->tcp_read_time_out);
				} else if(strstr(buff, "tcp_connect_time_out")) {
					sscanf(buff, "%s %d", label, &pc_list->tcp_connect_time_out);
				} else if(strstr(buff, "remote_dns_subnet")) {
					sscanf(buff, "%s %d", label, &pc_list->remote_dns_subnet);
					if(pc_list->remote_dns_subnet >= 256) {
						fprintf(stderr,
							"remote_dns_subnet: invalid value. requires a number between 0 and 255.\n");
						exit(1);
					}
				} else if(strstr(buff, "localnet")) {
					localaddr_arg *laddr_a = &pc_list->localnet_addr[pc_list->num_localnet_addr];
					if(sscanf(buff, "%s %21[^/]/%15s", label, local_in_addr_port, local_netmask) < 3) {
						fprintf(stderr, "localnet format error");
						exit(1);
					}
					/* clean previously used buffer */
					memset(local_in_port, 0, sizeof(local_in_port) / sizeof(local_in_port[0]));

					if(sscanf(local_in_addr_port, "%15[^:]:%5s", local_in_addr, local_in_port) < 2) {
						PDEBUG("added localnet: netaddr=%s, netmask=%s\n",
						       local_in_addr, local_netmask);
					} else {
						PDEBUG("added localnet: netaddr=%s, port=%s, netmask=%s\n",
						       local_in_addr, local_in_port, local_netmask);
					}
					if(pc_list->num_localnet_addr < MAX_LOCALNET) {
						int error;
						error = inet_pton(AF_INET, local_in_addr, &laddr_a->in_addr);
						if(error <= 0) {
							fprintf(stderr, "localnet address error\n");
							exit(1);
						}
						error = inet_pton(AF_INET, local_netmask, &laddr_a->netmask);
						if(error <= 0) {
							fprintf(stderr, "localnet netmask error\n");
							exit(1);
						}
						if(local_in_port[0]) {
							laddr_a->port = (short) atoi(local_in_port);
						} else {
							laddr_a->port = 0;
						}
						++pc_list->num_localnet_addr;
					} else {
						fprintf(stderr, "# of localnet exceed %d.\n", MAX_LOCALNET);
					}
				} else if(strstr(buff, "quiet_mode")) {
					proxychains_quiet_mode = 1;
				} else if(strstr(buff, "proxy_dns")) {
					proxychains_resolver = 1;
				}
			}
		}
	}
	
	/* If have a previous chain stored in the temp chain, copy
	   to global lists. This is needed for the last defined chain. */
	if (count) {
		proxy_chain_load_pdata(pc_curr, pd_list, count);
		count = 0;
	}
	
	fclose(file);
	//~ *proxy_count = count;
	got_chain_data = 1;
}

int get_chain_type(char *buff, chain_type *ct) {
	int i = 0;
	for (; i < MAX_CHAIN_TYPE; i++) {
		if (strstr(buff, chain_type_strmap[i])) {
			*ct = i;
			return 0;
		}
	}
	return 1;
}

int proxy_chain_list_load(proxy_chain_list *pc_list) {
	char *env = NULL;

	/* Create global library data */
	proxychains_chain_list = (proxy_chain_list*)malloc(sizeof(proxy_chain_list));
	if (proxychains_chain_list ==  NULL) {
		proxychains_write_log(LOG_PREFIX "Error failed to allocate proxy list object\n");
		exit(1);
	}
	
	/* Initialize proxychain library data */
	proxychains_chain_list->remote_dns_subnet = -1; // -1 means no remote dns
	//~ proxychains_chain_list->pc = NULL;
	proxychains_chain_list->count = 0;
	//~ proxychains_chain_list->localnet_addr = NULL;
	proxychains_chain_list->num_localnet_addr = 0;
	proxychains_chain_list->tcp_read_time_out = 4 * 1000;
	proxychains_chain_list->tcp_connect_time_out = 10 * 1000;
	//~ proxychains_chain_list->chain_selection = PROXYCHAINS_DEFAULT_CHAIN;
	proxychains_chain_list->selected = NULL;
	
	/* read the config file */
	get_chain_data(proxychains_chain_list);
	PDEBUG("Finished loading chain data\n");
	DUMP_PROXY_CHAIN_LIST(proxychains_chain_list);
	//~ DUMP_PROXY_CHAIN(proxychains_chain_list->pc[0]);
	
	env = getenv(PROXYCHAINS_CHAIN_ENV_VAR);
	if(!env)
		env = PROXYCHAINS_DEFAULT_CHAIN;
	if (!proxy_chain_list_set_selected(proxychains_chain_list, env)) {
		proxychains_write_log(LOG_PREFIX "Error chain list \"%s\" not found\n", env);
		exit(1);
	}
	return 0;
}

int proxy_chain_load_pdata(proxy_chain *pc, proxy_data *pd_list, int count) {
	pc->count = count;
	pc->pd = (proxy_data*)malloc(sizeof(proxy_data)*count);
	if (pc->pd ==  NULL) {
		proxychains_write_log(LOG_PREFIX "Error failed to allocate proxy data list for \"%s\" chain\n", pc->name);
		exit(1);
	}
	memcpy(pc->pd, pd_list, sizeof(proxy_data)*count);
	
	return 0;
}

proxy_chain* proxy_chain_list_set_selected(proxy_chain_list *pc_list, const char *chain_name) {
	int i = 0;
	for (; i < pc_list->count; i++) {
		if (!strcmp(chain_name, pc_list->pc[i]->name)) {
			pc_list->selected = pc_list->pc[i];
			return pc_list->pc[i];
		}
	}
	return NULL;
}

/*******  HOOK FUNCTIONS  *******/

int close(int fd) {
	/* prevent rude programs (like ssh) from closing our pipes */
	if(fd != req_pipefd[0]  && fd != req_pipefd[1] &&
	   fd != resp_pipefd[0] && fd != resp_pipefd[1]) {
		return true_close(fd);
	}
	errno = EINTR;
	return -1;
}

int connect(int sock, const struct sockaddr *addr, unsigned int len) {
	PFUNC();
	int socktype = 0, flags = 0, ret = 0;
	socklen_t optlen = 0;
	ip_type dest_ip;
#ifdef DEBUG
	char str[256];
#endif
	struct in_addr *p_addr_in;
	unsigned short port;
	size_t i;
	int remote_dns_connect = 0;
	INIT();
	optlen = sizeof(socktype);
	getsockopt(sock, SOL_SOCKET, SO_TYPE, &socktype, &optlen);
	if(!(SOCKFAMILY(*addr) == AF_INET && socktype == SOCK_STREAM))
		return true_connect(sock, addr, len);

	p_addr_in = &((struct sockaddr_in *) addr)->sin_addr;
	port = ntohs(((struct sockaddr_in *) addr)->sin_port);

#ifdef DEBUG
//      PDEBUG("localnet: %s; ", inet_ntop(AF_INET,&in_addr_localnet, str, sizeof(str)));
//      PDEBUG("netmask: %s; " , inet_ntop(AF_INET, &in_addr_netmask, str, sizeof(str)));
	PDEBUG("target: %s\n", inet_ntop(AF_INET, p_addr_in, str, sizeof(str)));
	PDEBUG("port: %d\n", port);
#endif

	// check if connect called from proxydns
        remote_dns_connect = (ntohl(p_addr_in->s_addr) >> 24 == proxychains_chain_list->remote_dns_subnet);

	for(i = 0; i < proxychains_chain_list->num_localnet_addr && !remote_dns_connect; i++) {
		if((proxychains_chain_list->localnet_addr[i].in_addr.s_addr & proxychains_chain_list->localnet_addr[i].netmask.s_addr)
		   == (p_addr_in->s_addr & proxychains_chain_list->localnet_addr[i].netmask.s_addr)) {
			if(!proxychains_chain_list->localnet_addr[i].port || proxychains_chain_list->localnet_addr[i].port == port) {
				PDEBUG("accessing localnet using true_connect\n");
				return true_connect(sock, addr, len);
			}
		}
	}

	flags = fcntl(sock, F_GETFL, 0);
	if(flags & O_NONBLOCK)
		fcntl(sock, F_SETFL, !O_NONBLOCK);

	dest_ip.as_int = SOCKADDR(*addr);

	ret = connect_proxy_chain(sock,
				  dest_ip,
				  SOCKPORT(*addr),
				  proxychains_chain_list->selected);

	fcntl(sock, F_SETFL, flags);
	if(ret != SUCCESS)
		errno = ECONNREFUSED;
	return ret;
}

static struct gethostbyname_data ghbndata;
struct hostent *gethostbyname(const char *name) {
	INIT();

	PDEBUG("gethostbyname: %s\n", name);

	if(proxychains_resolver)
		return proxy_gethostbyname(name, &ghbndata);
	else
		return true_gethostbyname(name);

	return NULL;
}

int getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res) {
	int ret = 0;

	INIT();

	PDEBUG("getaddrinfo: %s %s\n", node ? node : "null", service ? service : "null");

	if(proxychains_resolver)
		ret = proxy_getaddrinfo(node, service, hints, res);
	else
		ret = true_getaddrinfo(node, service, hints, res);

	return ret;
}

void freeaddrinfo(struct addrinfo *res) {
	INIT();

	PDEBUG("freeaddrinfo %p \n", res);

	if(!proxychains_resolver)
		true_freeaddrinfo(res);
	else
		proxy_freeaddrinfo(res);
	return;
}

int pc_getnameinfo(const struct sockaddr *sa, socklen_t salen, 
	           char *host, socklen_t hostlen, char *serv, 
	           socklen_t servlen, int flags)
{
	char ip_buf[16];
	int ret = 0;

	INIT();
	
	PFUNC();

	if(!proxychains_resolver) {
		ret = true_getnameinfo(sa, salen, host, hostlen, serv, servlen, flags);
	} else {
		if(salen < sizeof(struct sockaddr_in) || SOCKFAMILY(*sa) != AF_INET)
			return EAI_FAMILY;
		if(hostlen) {
			pc_stringfromipv4((unsigned char*) &(SOCKADDR_2(*sa)), ip_buf);
			if(snprintf(host, hostlen, "%s", ip_buf) >= hostlen)
				return EAI_OVERFLOW;
		}
		if(servlen) {
			if(snprintf(serv, servlen, "%d", ntohs(SOCKPORT(*sa))) >= servlen)
				return EAI_OVERFLOW;
		}
	}
	return ret;
}

struct hostent *gethostbyaddr(const void *addr, socklen_t len, int type) {
	static char buf[16];
	static char ipv4[4];
	static char *list[2];
	static char *aliases[1];
	static struct hostent he;

	INIT();

	PDEBUG("TODO: proper gethostbyaddr hook\n");

	if(!proxychains_resolver)
		return true_gethostbyaddr(addr, len, type);
	else {

		PDEBUG("len %u\n", len);
		if(len != 4)
			return NULL;
		he.h_name = buf;
		memcpy(ipv4, addr, 4);
		list[0] = ipv4;
		list[1] = NULL;
		he.h_addr_list = list;
		he.h_addrtype = AF_INET;
		aliases[0] = NULL;
		he.h_aliases = aliases;
		he.h_length = 4;
		pc_stringfromipv4((unsigned char *) addr, buf);
		return &he;
	}
	return NULL;
}
