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
#define     MAX_CHAIN 512

close_t true_close;
connect_t true_connect;
gethostbyname_t true_gethostbyname;
getaddrinfo_t true_getaddrinfo;
freeaddrinfo_t true_freeaddrinfo;
getnameinfo_t true_getnameinfo;
gethostbyaddr_t true_gethostbyaddr;
sendto_t true_sendto;

int tcp_read_time_out;
int tcp_connect_time_out;
chain_type proxychains_ct;
proxy_data proxychains_pd[MAX_CHAIN];
unsigned int proxychains_proxy_count = 0;
unsigned int proxychains_proxy_offset = 0;
int proxychains_got_chain_data = 0;
unsigned int proxychains_max_chain = 1;
int proxychains_quiet_mode = 0;
int proxychains_resolver = 0;
localaddr_arg localnet_addr[MAX_LOCALNET];
size_t num_localnet_addr = 0;
unsigned int remote_dns_subnet = 224;

pthread_once_t init_once = PTHREAD_ONCE_INIT;

static int init_l = 0;

static inline void get_chain_data(proxy_data * pd, unsigned int *proxy_count, chain_type * ct);

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

#include "allocator_thread.h"

const char *proxychains_get_version(void);

static void do_init(void) {
	srand(time(NULL));
	core_initialize();
	at_init();

	/* read the config file */
	get_chain_data(proxychains_pd, &proxychains_proxy_count, &proxychains_ct);
	DUMP_PROXY_CHAIN(proxychains_pd, proxychains_proxy_count);

	proxychains_write_log(LOG_PREFIX "DLL init: proxychains-ng %s\n", proxychains_get_version());

	SETUP_SYM(connect);
	SETUP_SYM(sendto);
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
static void get_chain_data(proxy_data * pd, unsigned int *proxy_count, chain_type * ct) {
	int count = 0, port_n = 0, list = 0;
	char buff[1024], type[1024], host[1024], user[1024];
	char *env;
	char local_in_addr_port[32];
	char local_in_addr[32], local_in_port[32], local_netmask[32];
	FILE *file = NULL;

	if(proxychains_got_chain_data)
		return;

	//Some defaults
	tcp_read_time_out = 4 * 1000;
	tcp_connect_time_out = 10 * 1000;
	*ct = DYNAMIC_TYPE;

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
			if(list) {
				if(count >= MAX_CHAIN)
					break;

				memset(&pd[count], 0, sizeof(proxy_data));

				pd[count].ps = PLAY_STATE;
				port_n = 0;

				int ret = sscanf(buff, "%s %s %d %s %s", type, host, &port_n, pd[count].user, pd[count].pass);
				if(ret < 3 || ret == EOF) {
					inv:
					fprintf(stderr, "error: invalid item in proxylist section: %s", buff);
					exit(1);
				}

				in_addr_t host_ip = inet_addr(host);
				if(host_ip == INADDR_NONE) {
					fprintf(stderr, "proxy %s has invalid value or is not numeric\n", host);
					exit(1);
				}
				pd[count].ip.as_int = (uint32_t) host_ip;
				pd[count].port = htons((unsigned short) port_n);

				if(!strcmp(type, "http")) {
					pd[count].pt = HTTP_TYPE;
				} else if(!strcmp(type, "socks4")) {
					pd[count].pt = SOCKS4_TYPE;
				} else if(!strcmp(type, "socks5")) {
					pd[count].pt = SOCKS5_TYPE;
				} else
					goto inv;

				if(pd[count].ip.as_int && port_n && pd[count].ip.as_int != (uint32_t) - 1)
					count++;
			} else {
				if(strstr(buff, "[ProxyList]")) {
					list = 1;
				} else if(strstr(buff, "random_chain")) {
					*ct = RANDOM_TYPE;
				} else if(strstr(buff, "strict_chain")) {
					*ct = STRICT_TYPE;
				} else if(strstr(buff, "dynamic_chain")) {
					*ct = DYNAMIC_TYPE;
				} else if(strstr(buff, "round_robin_chain")) {
					*ct = ROUND_ROBIN_TYPE;
				} else if(strstr(buff, "tcp_read_time_out")) {
					sscanf(buff, "%s %d", user, &tcp_read_time_out);
				} else if(strstr(buff, "tcp_connect_time_out")) {
					sscanf(buff, "%s %d", user, &tcp_connect_time_out);
				} else if(strstr(buff, "remote_dns_subnet")) {
					sscanf(buff, "%s %d", user, &remote_dns_subnet);
					if(remote_dns_subnet >= 256) {
						fprintf(stderr,
							"remote_dns_subnet: invalid value. requires a number between 0 and 255.\n");
						exit(1);
					}
				} else if(strstr(buff, "localnet")) {
					if(sscanf(buff, "%s %21[^/]/%15s", user, local_in_addr_port, local_netmask) < 3) {
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
					if(num_localnet_addr < MAX_LOCALNET) {
						int error;
						error =
						    inet_pton(AF_INET, local_in_addr,
							      &localnet_addr[num_localnet_addr].in_addr);
						if(error <= 0) {
							fprintf(stderr, "localnet address error\n");
							exit(1);
						}
						error =
						    inet_pton(AF_INET, local_netmask,
							      &localnet_addr[num_localnet_addr].netmask);
						if(error <= 0) {
							fprintf(stderr, "localnet netmask error\n");
							exit(1);
						}
						if(local_in_port[0]) {
							localnet_addr[num_localnet_addr].port =
							    (short) atoi(local_in_port);
						} else {
							localnet_addr[num_localnet_addr].port = 0;
						}
						++num_localnet_addr;
					} else {
						fprintf(stderr, "# of localnet exceed %d.\n", MAX_LOCALNET);
					}
				} else if(strstr(buff, "chain_len")) {
					char *pc;
					int len;
					pc = strchr(buff, '=');
					len = atoi(++pc);
					proxychains_max_chain = (len ? len : 1);
				} else if(strstr(buff, "quiet_mode")) {
					proxychains_quiet_mode = 1;
				} else if(strstr(buff, "proxy_dns")) {
					proxychains_resolver = 1;
				}
			}
		}
	}
	fclose(file);
	if(!count) {
		fprintf(stderr, "error: no valid proxy found in config\n");
		exit(1);
	}
	*proxy_count = count;
	proxychains_got_chain_data = 1;
}

/*******  HOOK FUNCTIONS  *******/

int close(int fd) {
	INIT();
	/* prevent rude programs (like ssh) from closing our pipes */
	if(fd != req_pipefd[0]  && fd != req_pipefd[1] &&
	   fd != resp_pipefd[0] && fd != resp_pipefd[1]) {
		return true_close(fd);
	}
	errno = EBADF;
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
        remote_dns_connect = (ntohl(p_addr_in->s_addr) >> 24 == remote_dns_subnet);

	for(i = 0; i < num_localnet_addr && !remote_dns_connect; i++) {
		if((localnet_addr[i].in_addr.s_addr & localnet_addr[i].netmask.s_addr)
		   == (p_addr_in->s_addr & localnet_addr[i].netmask.s_addr)) {
			if(!localnet_addr[i].port || localnet_addr[i].port == port) {
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
				  proxychains_pd, proxychains_proxy_count, proxychains_ct, proxychains_max_chain);

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

#ifndef MSG_FASTOPEN
#   define MSG_FASTOPEN 0x20000000
#endif

ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
	       const struct sockaddr *dest_addr, socklen_t addrlen) {
	if (flags & MSG_FASTOPEN) {
		if (!connect(sockfd, dest_addr, addrlen) && errno != EINPROGRESS) {
			return -1;
		}
		dest_addr = NULL;
		addrlen = 0;
		flags &= ~MSG_FASTOPEN;
	}
	return true_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
}
