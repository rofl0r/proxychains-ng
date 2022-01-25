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
#include <limits.h>
#include <ctype.h>
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
#include "rdns.h"

#undef 		satosin
#define     satosin(x)      ((struct sockaddr_in *) &(x))
#define     SOCKADDR(x)     (satosin(x)->sin_addr.s_addr)
#define     SOCKADDR_2(x)     (satosin(x)->sin_addr)
#define     SOCKPORT(x)     (satosin(x)->sin_port)
#define     SOCKFAMILY(x)     (satosin(x)->sin_family)
#define     MAX_CHAIN 512

#ifdef IS_SOLARIS
#undef connect
int __xnet_connect(int sock, const struct sockaddr *addr, unsigned int len);
connect_t true___xnet_connect;
#endif

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
enum dns_lookup_flavor proxychains_resolver = DNSLF_LIBC;
localaddr_arg localnet_addr[MAX_LOCALNET];
size_t num_localnet_addr = 0;
dnat_arg dnats[MAX_DNAT];
size_t num_dnats = 0;
unsigned int remote_dns_subnet = 224;

pthread_once_t init_once = PTHREAD_ONCE_INIT;

static int init_l = 0;

static void get_chain_data(proxy_data * pd, unsigned int *proxy_count, chain_type * ct);

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


#include "allocator_thread.h"

const char *proxychains_get_version(void);

static void setup_hooks(void);

static int close_fds[16];
static int close_fds_cnt = 0;

static unsigned get_rand_seed(void) {
#ifdef HAVE_CLOCK_GETTIME
	struct timespec now;
	clock_gettime(CLOCK_REALTIME, &now);
	return now.tv_sec ^ now.tv_nsec;
#else
	return time(NULL);
#endif
}

static void do_init(void) {
	srand(get_rand_seed());
	core_initialize();

	/* read the config file */
	get_chain_data(proxychains_pd, &proxychains_proxy_count, &proxychains_ct);
	DUMP_PROXY_CHAIN(proxychains_pd, proxychains_proxy_count);

	proxychains_write_log(LOG_PREFIX "DLL init: proxychains-ng %s\n", proxychains_get_version());

	setup_hooks();

	while(close_fds_cnt) true_close(close_fds[--close_fds_cnt]);
	init_l = 1;

	rdns_init(proxychains_resolver);
}

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


typedef enum {
	RS_PT_NONE = 0,
	RS_PT_SOCKS4,
	RS_PT_SOCKS5,
	RS_PT_HTTP
} rs_proxyType;

/*
  proxy_from_string() taken from rocksock network I/O library (C) rofl0r
  valid inputs:
	socks5://user:password@proxy.domain.com:port
	socks5://proxy.domain.com:port
	socks4://proxy.domain.com:port
	http://user:password@proxy.domain.com:port
	http://proxy.domain.com:port

	supplying port number is obligatory.
	user:pass@ part is optional for http and socks5.
	however, user:pass authentication is currently not implemented for http proxies.
  return 1 on success, 0 on error.
*/
static int proxy_from_string(const char *proxystring,
	char *type_buf,
	char* host_buf,
	int *port_n,
	char *user_buf,
	char* pass_buf)
{
	const char* p;
	rs_proxyType proxytype;

	size_t next_token = 6, ul = 0, pl = 0, hl;
	if(!proxystring[0] || !proxystring[1] || !proxystring[2] || !proxystring[3] || !proxystring[4] || !proxystring[5]) goto inv_string;
	if(*proxystring == 's') {
		switch(proxystring[5]) {
			case '5': proxytype = RS_PT_SOCKS5; break;
			case '4': proxytype = RS_PT_SOCKS4; break;
			default: goto inv_string;
		}
	} else if(*proxystring == 'h') {
		proxytype = RS_PT_HTTP;
		next_token = 4;
	} else goto inv_string;
	if(
	   proxystring[next_token++] != ':' ||
	   proxystring[next_token++] != '/' ||
	   proxystring[next_token++] != '/') goto inv_string;
	const char *at = strrchr(proxystring+next_token, '@');
	if(at) {
		if(proxytype == RS_PT_SOCKS4)
			return 0;
		p = strchr(proxystring+next_token, ':');
		if(!p || p >= at) goto inv_string;
		const char *u = proxystring+next_token;
		ul = p-u;
		p++;
		pl = at-p;
		if(proxytype == RS_PT_SOCKS5 && (ul > 255 || pl > 255))
			return 0;
		memcpy(user_buf, u, ul);
		user_buf[ul]=0;
		memcpy(pass_buf, p, pl);
		pass_buf[pl]=0;
		next_token += 2+ul+pl;
	} else {
		user_buf[0]=0;
		pass_buf[0]=0;
	}
	const char* h = proxystring+next_token;
	p = strchr(h, ':');
	if(!p) goto inv_string;
	hl = p-h;
	if(hl > 255)
		return 0;
	memcpy(host_buf, h, hl);
	host_buf[hl]=0;
	*port_n = atoi(p+1);
	switch(proxytype) {
		case RS_PT_SOCKS4:
			strcpy(type_buf, "socks4");
			break;
		case RS_PT_SOCKS5:
			strcpy(type_buf, "socks5");
			break;
		case RS_PT_HTTP:
			strcpy(type_buf, "http");
			break;
		default:
			return 0;
	}
	return 1;
inv_string:
	return 0;
}

static const char* bool_str(int bool_val) {
	if(bool_val) return "true";
	return "false";
}

#define STR_STARTSWITH(P, LIT) (!strncmp(P, LIT, sizeof(LIT)-1))
/* get configuration from config file */
static void get_chain_data(proxy_data * pd, unsigned int *proxy_count, chain_type * ct) {
	int count = 0, port_n = 0, list = 0;
	char buf[1024], type[1024], host[1024], user[1024];
	char *buff, *env, *p;
	char local_addr_port[64], local_addr[64], local_netmask[32];
	char dnat_orig_addr_port[32], dnat_new_addr_port[32];
	char dnat_orig_addr[32], dnat_orig_port[32], dnat_new_addr[32], dnat_new_port[32];
	char rdnsd_addr[32], rdnsd_port[8];
	FILE *file = NULL;

	if(proxychains_got_chain_data)
		return;

	PFUNC();

	//Some defaults
	tcp_read_time_out = 4 * 1000;
	tcp_connect_time_out = 10 * 1000;
	*ct = DYNAMIC_TYPE;

	env = get_config_path(getenv(PROXYCHAINS_CONF_FILE_ENV_VAR), buf, sizeof(buf));
	if( ( file = fopen(env, "r") ) == NULL )
	{
	        perror("couldnt read configuration file");
        	exit(1);
	}

	env = getenv(PROXYCHAINS_QUIET_MODE_ENV_VAR);
	if(env && *env == '1')
		proxychains_quiet_mode = 1;

	while(fgets(buf, sizeof(buf), file)) {
		buff = buf;
		/* remove leading whitespace */
		while(isspace(*buff)) buff++;
		/* remove trailing '\n' */
		if((p = strrchr(buff, '\n'))) *p = 0;
		p = buff + strlen(buff)-1;
		/* remove trailing whitespace */
		while(p >= buff && isspace(*p)) *(p--) = 0;
		if(!*buff || *buff == '#') continue; /* skip empty lines and comments */
		if(1) {
			/* proxylist has to come last */
			if(list) {
				if(count >= MAX_CHAIN)
					break;

				memset(&pd[count], 0, sizeof(proxy_data));

				pd[count].ps = PLAY_STATE;
				port_n = 0;

				int ret = sscanf(buff, "%s %s %d %s %s", type, host, &port_n, pd[count].user, pd[count].pass);
				if(ret < 3 || ret == EOF) {
					if(!proxy_from_string(buff, type, host, &port_n, pd[count].user, pd[count].pass)) {
						inv:
						fprintf(stderr, "error: invalid item in proxylist section: %s", buff);
						exit(1);
					}
				}

				memset(&pd[count].ip, 0, sizeof(pd[count].ip));
				pd[count].ip.is_v6 = !!strchr(host, ':');
				pd[count].port = htons((unsigned short) port_n);
				ip_type* host_ip = &pd[count].ip;
				if(1 != inet_pton(host_ip->is_v6 ? AF_INET6 : AF_INET, host, host_ip->addr.v6)) {
					if(*ct == STRICT_TYPE && proxychains_resolver >= DNSLF_RDNS_START && count > 0) {
						/* we can allow dns hostnames for all but the first proxy in the list if chaintype is strict, as remote lookup can be done */
						rdns_init(proxychains_resolver);
						ip_type4 internal_ip = at_get_ip_for_host(host, strlen(host));
						pd[count].ip.is_v6 = 0;
						host_ip->addr.v4 = internal_ip;
						if(internal_ip.as_int == IPT4_INVALID.as_int)
							goto inv_host;
					} else {
inv_host:
						fprintf(stderr, "proxy %s has invalid value or is not numeric\n", host);
						fprintf(stderr, "non-numeric ips are only allowed under the following circumstances:\n");
						fprintf(stderr, "chaintype == strict (%s), proxy is not first in list (%s), proxy_dns active (%s)\n\n", bool_str(*ct == STRICT_TYPE), bool_str(count > 0), rdns_resolver_string(proxychains_resolver));
						exit(1);
					}
				}

				if(!strcmp(type, "http")) {
					pd[count].pt = HTTP_TYPE;
				} else if(!strcmp(type, "raw")) {
					pd[count].pt = RAW_TYPE;
				} else if(!strcmp(type, "socks4")) {
					pd[count].pt = SOCKS4_TYPE;
				} else if(!strcmp(type, "socks5")) {
					pd[count].pt = SOCKS5_TYPE;
				} else
					goto inv;

				if(port_n)
					count++;
			} else {
				if(!strcmp(buff, "[ProxyList]")) {
					list = 1;
				} else if(!strcmp(buff, "random_chain")) {
					*ct = RANDOM_TYPE;
				} else if(!strcmp(buff, "strict_chain")) {
					*ct = STRICT_TYPE;
				} else if(!strcmp(buff, "dynamic_chain")) {
					*ct = DYNAMIC_TYPE;
				} else if(!strcmp(buff, "round_robin_chain")) {
					*ct = ROUND_ROBIN_TYPE;
				} else if(STR_STARTSWITH(buff, "tcp_read_time_out")) {
					sscanf(buff, "%s %d", user, &tcp_read_time_out);
				} else if(STR_STARTSWITH(buff, "tcp_connect_time_out")) {
					sscanf(buff, "%s %d", user, &tcp_connect_time_out);
				} else if(STR_STARTSWITH(buff, "remote_dns_subnet")) {
					sscanf(buff, "%s %u", user, &remote_dns_subnet);
					if(remote_dns_subnet >= 256) {
						fprintf(stderr,
							"remote_dns_subnet: invalid value. requires a number between 0 and 255.\n");
						exit(1);
					}
				} else if(STR_STARTSWITH(buff, "localnet")) {
					char colon, extra, right_bracket[2];
					unsigned short local_port = 0, local_prefix;
					int local_family, n, valid;
					if(sscanf(buff, "%s %53[^/]/%15s%c", user, local_addr_port, local_netmask, &extra) != 3) {
						fprintf(stderr, "localnet format error");
						exit(1);
					}
					p = strchr(local_addr_port, ':');
					if(!p || p == strrchr(local_addr_port, ':')) {
						local_family = AF_INET;
						n = sscanf(local_addr_port, "%15[^:]%c%5hu%c", local_addr, &colon, &local_port, &extra);
						valid = n == 1 || (n == 3 && colon == ':');
					} else if(local_addr_port[0] == '[') {
						local_family = AF_INET6;
						n = sscanf(local_addr_port, "[%45[^][]%1[]]%c%5hu%c", local_addr, right_bracket, &colon, &local_port, &extra);
						valid = n == 2 || (n == 4 && colon == ':');
					} else {
						local_family = AF_INET6;
						valid = sscanf(local_addr_port, "%45[^][]%c", local_addr, &extra) == 1;
					}
					if(!valid) {
						fprintf(stderr, "localnet address or port error\n");
						exit(1);
					}
					if(local_port) {
						PDEBUG("added localnet: netaddr=%s, port=%u, netmask=%s\n",
						       local_addr, local_port, local_netmask);
					} else {
						PDEBUG("added localnet: netaddr=%s, netmask=%s\n",
						       local_addr, local_netmask);
					}
					if(num_localnet_addr < MAX_LOCALNET) {
						localnet_addr[num_localnet_addr].family = local_family;
						localnet_addr[num_localnet_addr].port = local_port;
						valid = 0;
						if (local_family == AF_INET) {
							valid =
							    inet_pton(local_family, local_addr,
							              &localnet_addr[num_localnet_addr].in_addr) > 0;
						} else if(local_family == AF_INET6) {
							valid =
							    inet_pton(local_family, local_addr,
							              &localnet_addr[num_localnet_addr].in6_addr) > 0;
						}
						if(!valid) {
							fprintf(stderr, "localnet address error\n");
							exit(1);
						}
						if(local_family == AF_INET && strchr(local_netmask, '.')) {
							valid =
							    inet_pton(local_family, local_netmask,
							              &localnet_addr[num_localnet_addr].in_mask) > 0;
						} else {
							valid = sscanf(local_netmask, "%hu%c", &local_prefix, &extra) == 1;
							if (valid) {
								if(local_family == AF_INET && local_prefix <= 32) {
									localnet_addr[num_localnet_addr].in_mask.s_addr =
										htonl(0xFFFFFFFFu << (32u - local_prefix));
								} else if(local_family == AF_INET6 && local_prefix <= 128) {
									localnet_addr[num_localnet_addr].in6_prefix =
										local_prefix;
								} else {
									valid = 0;
								}
							}
						}
						if(!valid) {
							fprintf(stderr, "localnet netmask error\n");
							exit(1);
						}
						++num_localnet_addr;
					} else {
						fprintf(stderr, "# of localnet exceed %d.\n", MAX_LOCALNET);
					}
				} else if(STR_STARTSWITH(buff, "chain_len")) {
					char *pc;
					int len;
					pc = strchr(buff, '=');
					if(!pc) {
						fprintf(stderr, "error: missing equals sign '=' in chain_len directive.\n");
						exit(1);
					}
					len = atoi(++pc);
					proxychains_max_chain = (len ? len : 1);
				} else if(!strcmp(buff, "quiet_mode")) {
					proxychains_quiet_mode = 1;
				} else if(!strcmp(buff, "proxy_dns_old")) {
					proxychains_resolver = DNSLF_FORKEXEC;
				} else if(!strcmp(buff, "proxy_dns")) {
					proxychains_resolver = DNSLF_RDNS_THREAD;
				} else if(STR_STARTSWITH(buff, "proxy_dns_daemon")) {
					struct sockaddr_in rdns_server_buffer;

					if(sscanf(buff, "%s %15[^:]:%5s", user, rdnsd_addr, rdnsd_port) < 3) {
						fprintf(stderr, "proxy_dns_daemon format error\n");
						exit(1);
					}
					rdns_server_buffer.sin_family = AF_INET;
					int error = inet_pton(AF_INET, rdnsd_addr, &rdns_server_buffer.sin_addr);
					if(error <= 0) {
						fprintf(stderr, "bogus proxy_dns_daemon address\n");
						exit(1);
					}
					rdns_server_buffer.sin_port = htons(atoi(rdnsd_port));
					proxychains_resolver = DNSLF_RDNS_DAEMON;
					rdns_set_daemon(&rdns_server_buffer);
				} else if(STR_STARTSWITH(buff, "dnat")) {
					if(sscanf(buff, "%s %21[^ ] %21s\n", user, dnat_orig_addr_port, dnat_new_addr_port) < 3) {
						fprintf(stderr, "dnat format error");
						exit(1);
					}
					/* clean previously used buffer */
					memset(dnat_orig_port, 0, sizeof(dnat_orig_port) / sizeof(dnat_orig_port[0]));
					memset(dnat_new_port, 0, sizeof(dnat_new_port) / sizeof(dnat_new_port[0]));

					(void)sscanf(dnat_orig_addr_port, "%15[^:]:%5s", dnat_orig_addr, dnat_orig_port);
					(void)sscanf(dnat_new_addr_port, "%15[^:]:%5s", dnat_new_addr, dnat_new_port);

					if(num_dnats < MAX_DNAT) {
						int error;
						error =
						    inet_pton(AF_INET, dnat_orig_addr,
							      &dnats[num_dnats].orig_dst);
						if(error <= 0) {
							fprintf(stderr, "dnat original destination address error\n");
							exit(1);
						}

						error =
						    inet_pton(AF_INET, dnat_new_addr,
							      &dnats[num_dnats].new_dst);
						if(error <= 0) {
							fprintf(stderr, "dnat effective destination address error\n");
							exit(1);
						}

						if(dnat_orig_port[0]) {
							dnats[num_dnats].orig_port =
							    (short) atoi(dnat_orig_port);
						} else {
							dnats[num_dnats].orig_port = 0;
						}

						if(dnat_new_port[0]) {
							dnats[num_dnats].new_port =
							    (short) atoi(dnat_new_port);
						} else {
							dnats[num_dnats].new_port = 0;
						}

						PDEBUG("added dnat: orig-dst=%s orig-port=%d new-dst=%s new-port=%d\n", dnat_orig_addr, dnats[num_dnats].orig_port, dnat_new_addr, dnats[num_dnats].new_port);
						++num_dnats;
					} else {
						fprintf(stderr, "# of dnat exceed %d.\n", MAX_DNAT);
					}
				}
			}
		}
	}
#ifndef BROKEN_FCLOSE
	fclose(file);
#endif
	if(!count) {
		fprintf(stderr, "error: no valid proxy found in config\n");
		exit(1);
	}
	*proxy_count = count;
	proxychains_got_chain_data = 1;
	PDEBUG("proxy_dns: %s\n", rdns_resolver_string(proxychains_resolver));
}

/*******  HOOK FUNCTIONS  *******/

#define EXPAND( args...) args
#ifdef MONTEREY_HOOKING
#define HOOKFUNC(R, N, args...) R pxcng_ ## N ( EXPAND(args) )
#else
#define HOOKFUNC(R, N, args...) R N ( EXPAND(args) )
#endif

HOOKFUNC(int, close, int fd) {
	if(!init_l) {
		if(close_fds_cnt>=(sizeof close_fds/sizeof close_fds[0])) goto err;
		close_fds[close_fds_cnt++] = fd;
		errno = 0;
		return 0;
	}
	if(proxychains_resolver != DNSLF_RDNS_THREAD) return true_close(fd);

	/* prevent rude programs (like ssh) from closing our pipes */
	if(fd != req_pipefd[0]  && fd != req_pipefd[1] &&
	   fd != resp_pipefd[0] && fd != resp_pipefd[1]) {
		return true_close(fd);
	}
	err:
	errno = EBADF;
	return -1;
}
static int is_v4inv6(const struct in6_addr *a) {
	return !memcmp(a->s6_addr, "\0\0\0\0\0\0\0\0\0\0\xff\xff", 12);
}

HOOKFUNC(int, connect, int sock, const struct sockaddr *addr, unsigned int len) {
	INIT();
	PFUNC();

	int socktype = 0, flags = 0, ret = 0;
	socklen_t optlen = 0;
	ip_type dest_ip;
	DEBUGDECL(char str[256]);

	struct in_addr *p_addr_in;
	struct in6_addr *p_addr_in6;
	dnat_arg *dnat = NULL;
	unsigned short port;
	size_t i;
	int remote_dns_connect = 0;
	optlen = sizeof(socktype);
	sa_family_t fam = SOCKFAMILY(*addr);
	getsockopt(sock, SOL_SOCKET, SO_TYPE, &socktype, &optlen);
	if(!((fam  == AF_INET || fam == AF_INET6) && socktype == SOCK_STREAM))
		return true_connect(sock, addr, len);

	int v6 = dest_ip.is_v6 = fam == AF_INET6;

	p_addr_in = &((struct sockaddr_in *) addr)->sin_addr;
	p_addr_in6 = &((struct sockaddr_in6 *) addr)->sin6_addr;
	port = !v6 ? ntohs(((struct sockaddr_in *) addr)->sin_port)
	           : ntohs(((struct sockaddr_in6 *) addr)->sin6_port);
	struct in_addr v4inv6;
	if(v6 && is_v4inv6(p_addr_in6)) {
		memcpy(&v4inv6.s_addr, &p_addr_in6->s6_addr[12], 4);
		v6 = dest_ip.is_v6 = 0;
		p_addr_in = &v4inv6;
	}
	if(!v6 && !memcmp(p_addr_in, "\0\0\0\0", 4)) {
		errno = ECONNREFUSED;
		return -1;
	}

//      PDEBUG("localnet: %s; ", inet_ntop(AF_INET,&in_addr_localnet, str, sizeof(str)));
//      PDEBUG("netmask: %s; " , inet_ntop(AF_INET, &in_addr_netmask, str, sizeof(str)));
	PDEBUG("target: %s\n", inet_ntop(v6 ? AF_INET6 : AF_INET, v6 ? (void*)p_addr_in6 : (void*)p_addr_in, str, sizeof(str)));
	PDEBUG("port: %d\n", port);

	// check if connect called from proxydns
        remote_dns_connect = !v6 && (ntohl(p_addr_in->s_addr) >> 24 == remote_dns_subnet);

	// more specific first
	if (!v6) for(i = 0; i < num_dnats && !remote_dns_connect && !dnat; i++)
		if(dnats[i].orig_dst.s_addr == p_addr_in->s_addr)
			if(dnats[i].orig_port && (dnats[i].orig_port == port))
				dnat = &dnats[i];

	if (!v6) for(i = 0; i < num_dnats && !remote_dns_connect && !dnat; i++)
		if(dnats[i].orig_dst.s_addr == p_addr_in->s_addr)
			if(!dnats[i].orig_port)
				dnat = &dnats[i];

	if (dnat) {
		p_addr_in = &dnat->new_dst;
		if (dnat->new_port)
			port = dnat->new_port;
	}

	for(i = 0; i < num_localnet_addr && !remote_dns_connect; i++) {
		if (localnet_addr[i].port && localnet_addr[i].port != port)
			continue;
		if (localnet_addr[i].family != (v6 ? AF_INET6 : AF_INET))
			continue;
		if (v6) {
			size_t prefix_bytes = localnet_addr[i].in6_prefix / CHAR_BIT;
			size_t prefix_bits = localnet_addr[i].in6_prefix % CHAR_BIT;
			if (prefix_bytes && memcmp(p_addr_in6->s6_addr, localnet_addr[i].in6_addr.s6_addr, prefix_bytes) != 0)
				continue;
			if (prefix_bits && (p_addr_in6->s6_addr[prefix_bytes] ^ localnet_addr[i].in6_addr.s6_addr[prefix_bytes]) >> (CHAR_BIT - prefix_bits))
				continue;
		} else {
			if((p_addr_in->s_addr ^ localnet_addr[i].in_addr.s_addr) & localnet_addr[i].in_mask.s_addr)
				continue;
		}
		PDEBUG("accessing localnet using true_connect\n");
		return true_connect(sock, addr, len);
	}

	flags = fcntl(sock, F_GETFL, 0);
	if(flags & O_NONBLOCK)
		fcntl(sock, F_SETFL, !O_NONBLOCK);

	memcpy(dest_ip.addr.v6, v6 ? (void*)p_addr_in6 : (void*)p_addr_in, v6?16:4);

	ret = connect_proxy_chain(sock,
				  dest_ip,
				  htons(port),
				  proxychains_pd, proxychains_proxy_count, proxychains_ct, proxychains_max_chain);

	fcntl(sock, F_SETFL, flags);
	if(ret != SUCCESS)
		errno = ECONNREFUSED;
	return ret;
}

#ifdef IS_SOLARIS
HOOKFUNC(int, __xnet_connect, int sock, const struct sockaddr *addr, unsigned int len)
	return connect(sock, addr, len);
}
#endif

static struct gethostbyname_data ghbndata;
HOOKFUNC(struct hostent*, gethostbyname, const char *name) {
	INIT();
	PDEBUG("gethostbyname: %s\n", name);

	if(proxychains_resolver == DNSLF_FORKEXEC)
		return proxy_gethostbyname_old(name);
	else if(proxychains_resolver == DNSLF_LIBC)
		return true_gethostbyname(name);
	else
		return proxy_gethostbyname(name, &ghbndata);

	return NULL;
}

HOOKFUNC(int, getaddrinfo, const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res) {
	INIT();
	PDEBUG("getaddrinfo: %s %s\n", node ? node : "null", service ? service : "null");

	if(proxychains_resolver != DNSLF_LIBC)
		return proxy_getaddrinfo(node, service, hints, res);
	else
		return true_getaddrinfo(node, service, hints, res);
}

HOOKFUNC(void, freeaddrinfo, struct addrinfo *res) {
	INIT();
	PDEBUG("freeaddrinfo %p \n", (void *) res);

	if(proxychains_resolver == DNSLF_LIBC)
		true_freeaddrinfo(res);
	else
		proxy_freeaddrinfo(res);
}

HOOKFUNC(int, getnameinfo, const struct sockaddr *sa, socklen_t salen,
	           char *host, GN_NODELEN_T hostlen, char *serv,
	           GN_SERVLEN_T servlen, GN_FLAGS_T flags)
{
	INIT();
	PFUNC();

	if(proxychains_resolver == DNSLF_LIBC) {
		return true_getnameinfo(sa, salen, host, hostlen, serv, servlen, flags);
	} else {
		if(!salen || !(SOCKFAMILY(*sa) == AF_INET || SOCKFAMILY(*sa) == AF_INET6))
			return EAI_FAMILY;
		int v6 = SOCKFAMILY(*sa) == AF_INET6;
		if(salen < (v6?sizeof(struct sockaddr_in6):sizeof(struct sockaddr_in)))
			return EAI_FAMILY;
		if(hostlen) {
			unsigned char v4inv6buf[4];
			const void *ip = v6 ? (void*)&((struct sockaddr_in6*)sa)->sin6_addr
			                    : (void*)&((struct sockaddr_in*)sa)->sin_addr;
			unsigned scopeid = 0;
			if(v6) {
				if(is_v4inv6(&((struct sockaddr_in6*)sa)->sin6_addr)) {
					memcpy(v4inv6buf, &((struct sockaddr_in6*)sa)->sin6_addr.s6_addr[12], 4);
					ip = v4inv6buf;
					v6 = 0;
				} else
					scopeid = ((struct sockaddr_in6 *)sa)->sin6_scope_id;
			}
			if(!inet_ntop(v6?AF_INET6:AF_INET,ip,host,hostlen))
				return EAI_OVERFLOW;
			if(scopeid) {
				size_t l = strlen(host);
				if(snprintf(host+l, hostlen-l, "%%%u", scopeid) >= hostlen-l)
					return EAI_OVERFLOW;
			}
		}
		if(servlen) {
			if(snprintf(serv, servlen, "%d", ntohs(SOCKPORT(*sa))) >= servlen)
				return EAI_OVERFLOW;
		}
	}
	return 0;
}

HOOKFUNC(struct hostent*, gethostbyaddr, const void *addr, socklen_t len, int type) {
	INIT();
	PDEBUG("TODO: proper gethostbyaddr hook\n");

	static char buf[16];
	static char ipv4[4];
	static char *list[2];
	static char *aliases[1];
	static struct hostent he;

	if(proxychains_resolver == DNSLF_LIBC)
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

HOOKFUNC(ssize_t, sendto, int sockfd, const void *buf, size_t len, int flags,
	       const struct sockaddr *dest_addr, socklen_t addrlen) {
	INIT();
	PFUNC();
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

#ifdef MONTEREY_HOOKING
#define SETUP_SYM(X) do { if (! true_ ## X ) true_ ## X = &X; } while(0)
#else
#define SETUP_SYM(X) do { if (! true_ ## X ) true_ ## X = load_sym( # X, X ); } while(0)
#endif

static void setup_hooks(void) {
	SETUP_SYM(connect);
	SETUP_SYM(sendto);
	SETUP_SYM(gethostbyname);
	SETUP_SYM(getaddrinfo);
	SETUP_SYM(freeaddrinfo);
	SETUP_SYM(gethostbyaddr);
	SETUP_SYM(getnameinfo);
#ifdef IS_SOLARIS
	SETUP_SYM(__xnet_connect);
#endif
	SETUP_SYM(close);
}

#ifdef MONTEREY_HOOKING

#define DYLD_INTERPOSE(_replacement,_replacee) \
   __attribute__((used)) static struct{ const void* replacement; const void* replacee; } _interpose_##_replacee \
   __attribute__((section ("__DATA,__interpose"))) = { (const void*)(unsigned long)&_replacement, (const void*)(unsigned long)&_replacee };
#define DYLD_HOOK(F) DYLD_INTERPOSE(pxcng_ ## F, F)

DYLD_HOOK(connect);
DYLD_HOOK(sendto);
DYLD_HOOK(gethostbyname);
DYLD_HOOK(getaddrinfo);
DYLD_HOOK(freeaddrinfo);
DYLD_HOOK(gethostbyaddr);
DYLD_HOOK(getnameinfo);
DYLD_HOOK(close);

#endif
