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

#include <sys/stat.h>




#include "core.h"
#include "common.h"
#include "rdns.h"
#include "mutex.h"

#undef 		satosin
#define     satosin(x)      ((struct sockaddr_in *) &(x))
#define     SOCKADDR(x)     (satosin(x)->sin_addr.s_addr)
#define     SOCKADDR_2(x)     (satosin(x)->sin_addr)
#define     SOCKPORT(x)     (satosin(x)->sin_port)
#define     SOCKFAMILY(x)     (satosin(x)->sin_family)
#define     MAX_CHAIN 512
#define 	RECV_BUFFER_SIZE 65536 //Should be larger than any possible UDP packet

#ifdef IS_SOLARIS
#undef connect
int __xnet_connect(int sock, const struct sockaddr *addr, unsigned int len);
connect_t true___xnet_connect;
#endif

close_t true_close;
close_range_t true_close_range;
connect_t true_connect;
gethostbyname_t true_gethostbyname;
getaddrinfo_t true_getaddrinfo;
freeaddrinfo_t true_freeaddrinfo;
getnameinfo_t true_getnameinfo;
gethostbyaddr_t true_gethostbyaddr;
sendto_t true_sendto;
send_t true_send;
recv_t true_recv;
recvfrom_t true_recvfrom;
sendmsg_t true_sendmsg;
recvmsg_t true_recvmsg;
sendmmsg_t true_sendmmsg;
getpeername_t true_getpeername;
read_t true_read;
write_t true_write;

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

udp_relay_chain_list relay_chains = {NULL, NULL};
pthread_mutex_t relay_chains_mutex;

pthread_once_t init_once = PTHREAD_ONCE_INIT;

static int init_l = 0;

static void get_chain_data(proxy_data * pd, unsigned int *proxy_count, chain_type * ct);

static void* load_sym(char* symname, void* proxyfunc, int is_mandatory) {
	void *funcptr = dlsym(RTLD_NEXT, symname);

	if(is_mandatory && !funcptr) {
		fprintf(stderr, "Cannot load symbol '%s' %s\n", symname, dlerror());
		exit(1);
	} else if (!funcptr) {
		return funcptr;
	} else {
		PDEBUG("loaded symbol '%s'" " real addr %p  wrapped addr %p\n", symname, funcptr, proxyfunc);
	}
	if(funcptr == proxyfunc) {
		PDEBUG("circular reference detected, aborting!\n");
		abort();
	}
	return funcptr;
}

#include "allocator_thread.h"

const char *proxychains_get_version(void);

static void setup_hooks(void);

typedef struct {
	unsigned int first, last, flags;
} close_range_args_t;

/* If there is some `close` or `close_range` system call before do_init, 
   we buffer it, and actually execute them in do_init. */
static int close_fds[16];
static int close_fds_cnt = 0;
static close_range_args_t close_range_buffer[16];
static int close_range_buffer_cnt = 0;

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
	char *env;

	srand(get_rand_seed());
	MUTEX_INIT(&relay_chains_mutex);
	core_initialize();

	env = getenv(PROXYCHAINS_QUIET_MODE_ENV_VAR);
	if(env && *env == '1')
		proxychains_quiet_mode = 1;

	proxychains_write_log(LOG_PREFIX "DLL init: proxychains-ng %s\n", proxychains_get_version());

	setup_hooks();

	/* read the config file */
	get_chain_data(proxychains_pd, &proxychains_proxy_count, &proxychains_ct);
	DUMP_PROXY_CHAIN(proxychains_pd, proxychains_proxy_count);

	while(close_fds_cnt) true_close(close_fds[--close_fds_cnt]);
	while(close_range_buffer_cnt) {
		int i = --close_range_buffer_cnt;
		true_close_range(close_range_buffer[i].first, close_range_buffer[i].last, close_range_buffer[i].flags);
	}
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
#if __GNUC__+0 > 2
__attribute__((constructor))
static void gcc_init(void) {
	init_lib_wrapper(__FUNCTION__);
}
#define INIT() do {} while(0)
#else
#define INIT() init_lib_wrapper(__FUNCTION__)
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
						ip_type4 internal_ip = rdns_get_ip_for_host(host, strlen(host));
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
	PFUNC();

	if(!init_l) {
		if(close_fds_cnt>=(sizeof close_fds/sizeof close_fds[0])) goto err;
		close_fds[close_fds_cnt++] = fd;
		errno = 0;
		return 0;
	}

	/***** UDP STUFF *******/
	//PDEBUG("checking if a relay chain is opened for fd %d\n", fd);
	udp_relay_chain* relay_chain = NULL;

	PDEBUG("waiting for mutex\n");
	MUTEX_LOCK(&relay_chains_mutex);
	PDEBUG("got mutex\n");
	relay_chain = get_relay_chain(relay_chains, fd);
	if(NULL != relay_chain){
		PDEBUG("fd %d corresponds to chain %x, closing it\n", fd, relay_chain);
		free_relay_chain_contents(relay_chain);
		del_relay_chain(&relay_chains, relay_chain);
		PDEBUG("chain %x corresponding to fd %d closed\n", relay_chain, fd);
		DUMP_RELAY_CHAINS_LIST(relay_chains);
	}
	


	/***** END UDP STUFF *******/

	if(proxychains_resolver != DNSLF_RDNS_THREAD){
		MUTEX_UNLOCK(&relay_chains_mutex);
		return true_close(fd);
	}

	/* prevent rude programs (like ssh) from closing our pipes */
	if(fd != req_pipefd[0]  && fd != req_pipefd[1] &&
	   fd != resp_pipefd[0] && fd != resp_pipefd[1]) {
		MUTEX_UNLOCK(&relay_chains_mutex);
		return true_close(fd);
	}
	err:
	errno = EBADF;
	MUTEX_UNLOCK(&relay_chains_mutex);
	return -1;
}

static int is_v4inv6(const struct in6_addr *a) {
	return !memcmp(a->s6_addr, "\0\0\0\0\0\0\0\0\0\0\xff\xff", 12);
}

static void intsort(int *a, int n) {
	int i, j, s;
	for(i=0; i<n; ++i)
		for(j=i+1; j<n; ++j)
			if(a[j] < a[i]) {
				s = a[i];
				a[i] = a[j];
				a[j] = s;
			}
}

/* Warning: Linux manual says the third arg is `unsigned int`, but unistd.h says `int`. */
HOOKFUNC(int, close_range, unsigned first, unsigned last, int flags) {
	PFUNC();
	if(true_close_range == NULL) {
		fprintf(stderr, "Calling close_range, but this platform does not provide this system call. ");
		return -1;
	}
	if(!init_l) {
		/* push back to cache, and delay the execution. */
		if(close_range_buffer_cnt >= (sizeof close_range_buffer / sizeof close_range_buffer[0])) {
			errno = ENOMEM;
			return -1;
		}
		int i = close_range_buffer_cnt++;
		close_range_buffer[i].first = first;
		close_range_buffer[i].last = last;
		close_range_buffer[i].flags = flags;
		return errno = 0;
	}
	if(proxychains_resolver != DNSLF_RDNS_THREAD) return true_close_range(first, last, flags);

	/* prevent rude programs (like ssh) from closing our pipes */
	int res = 0, uerrno = 0, i;
	int protected_fds[] = {req_pipefd[0], req_pipefd[1], resp_pipefd[0], resp_pipefd[1]};
	intsort(protected_fds, 4);
	/* We are skipping protected_fds while calling true_close_range()
	 * If protected_fds cut the range into some sub-ranges, we close sub-ranges BEFORE cut point in the loop. 
	 * [first, cut1-1] , [cut1+1, cut2-1] , [cut2+1, cut3-1]
	 * Finally, we delete the remaining sub-range, outside the loop. [cut3+1, tail]
	 */
	int next_fd_to_close = first;
	for(i = 0; i < 4; ++i) {
		if(protected_fds[i] < first || protected_fds[i] > last)
			continue;
		int prev = (i == 0 || protected_fds[i-1] < first) ? first : protected_fds[i-1]+1;
		if(prev != protected_fds[i]) {
			if(-1 == true_close_range(prev, protected_fds[i]-1, flags)) {
				res = -1;
				uerrno = errno;
			}
		}
		next_fd_to_close = protected_fds[i]+1;
	}
	if(next_fd_to_close <= last) {
		if(-1 == true_close_range(next_fd_to_close, last, flags)) {
			res = -1;
			uerrno = errno;
		}
	}
	errno = uerrno;
	return res;
}

HOOKFUNC(int, getpeername, int sockfd, struct sockaddr *restrict addr, socklen_t *restrict addrlen){
	INIT();
	PFUNC();

	int socktype = 0;
	socklen_t optlen = 0;
	optlen = sizeof(socktype);
	getsockopt(sockfd, SOL_SOCKET, SO_TYPE, &socktype, &optlen);
	if( socktype != SOCK_DGRAM){
		PDEBUG("sockfd %d is not a SOCK_DGRAM socket, returning to true_getpeername\n", sockfd);
		return true_getpeername(sockfd, addr, addrlen);
	}
	PDEBUG("sockfd %d is a SOCK_DGRAM socket\n", sockfd);

	struct sockaddr_storage sock_addr;
	socklen_t sock_addr_len = sizeof(sock_addr);
	if(SUCCESS != getsockname(sockfd, (struct sockaddr *)&sock_addr, &sock_addr_len )){
		PDEBUG("error getsockname, errno=%d. Returning to true_getpeernam()\n", errno);
		return true_getpeername(sockfd, addr, addrlen);
	}
	sa_family_t fam = SOCKFAMILY(sock_addr);
	if(!(fam  == AF_INET || fam == AF_INET6)){
		PDEBUG("sockfd %d address familiy is not a AF_INET or AF_INET6, returning to true_getpeername\n", sockfd);
		return true_getpeername(sockfd, addr, addrlen);
	}

	PDEBUG("sockfd %d's address family is AF_INET or AF_INET6\n", sockfd);

	
	/* BEGIN UDP STUFF*/


	// Check if a relay chain exists for the socket
	PDEBUG("waiting for mutex\n");
	MUTEX_LOCK(&relay_chains_mutex);
	PDEBUG("got mutex\n");
	udp_relay_chain* relay_chain = get_relay_chain(relay_chains, sockfd);
	if(relay_chain == NULL){
		PDEBUG("no relay chain exists for socket %d, returning true_getpeername()\n", sockfd);
		MUTEX_UNLOCK(&relay_chains_mutex);
		return true_getpeername(sockfd, addr, addrlen);
	}

	// Check if a connected peer address is stored in the relay chain structure
	if(relay_chain->connected_peer_addr == NULL){
		PDEBUG("no connected peer address is stored for socket %d, returning true_getpeername()\n", sockfd);
		MUTEX_UNLOCK(&relay_chains_mutex);
		return true_getpeername(sockfd, addr, addrlen);			
	}

	// If a connected peer address is stored in the relay chain structure, return it

	socklen_t provided_addr_len = *addrlen;
	

	size_t min = (provided_addr_len<relay_chain->connected_peer_addr_len)?provided_addr_len:relay_chain->connected_peer_addr_len;
	memcpy(addr, relay_chain->connected_peer_addr, min);

	*addrlen =  min;

	MUTEX_UNLOCK(&relay_chains_mutex);
	return SUCCESS;

	/* END UDP STUFF */

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
	
	/* BEGIN UDP STUFF*/
	if(((fam  == AF_INET || fam == AF_INET6) && socktype == SOCK_DGRAM)){
		PDEBUG("connect() on an UDP socket\n");

		// Check if a relay chain is already opened for the socket fd, otherwise open it
		PDEBUG("waiting for mutex\n");
		MUTEX_LOCK(&relay_chains_mutex);
		PDEBUG("got mutex\n");
		udp_relay_chain* relay_chain = get_relay_chain(relay_chains, sock);
		if(relay_chain == NULL){
			// No chain is opened for this socket, open one
			PDEBUG("opening new chain of relays for %d\n", sock);
			if(NULL == (relay_chain = open_relay_chain(proxychains_pd, proxychains_proxy_count, proxychains_ct, proxychains_max_chain))){
				PDEBUG("could not open a chain of relay\n");
				errno = ECONNREFUSED;
				MUTEX_UNLOCK(&relay_chains_mutex);
				return -1;
			}
			relay_chain->sockfd = sock;
			add_relay_chain(&relay_chains, relay_chain);
			DUMP_RELAY_CHAINS_LIST(relay_chains);
		}
		


		// Store the peer address in the relay chain structure, in order to be able to retrieve it in subsequent calls to send(), sendmsg(), ...
		set_connected_peer_addr(relay_chain, addr, len);


		// Connect the socket to the relay chain's head, so that subsequent calls to poll(), recv(), recvfrom(), ... can return data comming from this peer
		
		int v6 = relay_chain->head->bnd_addr.is_v6 == ATYP_V6;

		struct sockaddr_in addr = {
			.sin_family = AF_INET,
			.sin_port = relay_chain->head->bnd_port,
			.sin_addr.s_addr = (in_addr_t) relay_chain->head->bnd_addr.addr.v4.as_int,
		};
		struct sockaddr_in6 addr6 = {
			.sin6_family = AF_INET6,
			.sin6_port = relay_chain->head->bnd_port,
		};
		if(v6) memcpy(&addr6.sin6_addr.s6_addr, relay_chain->head->bnd_addr.addr.v6, 16);
		
		MUTEX_UNLOCK(&relay_chains_mutex);	
		return true_connect(sock, (struct sockaddr *) (v6?(void*)&addr6:(void*)&addr), v6?sizeof(addr6):sizeof(addr)  );
	}

	/* END UDP STUFF*/

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

	if(proxychains_resolver != DNSLF_LIBC){
		PDEBUG("using proxy_getaddrinfo()\n");
		return proxy_getaddrinfo(node, service, hints, res);
	}
	else{
		return true_getaddrinfo(node, service, hints, res);
	}
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

		return true_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
	}

	DEBUGDECL(char str[256]);

	// Check that sockfd is a SOCK_DGRAM socket with an AF_INET or AF_INET6 address
	int socktype = 0, ret = 0;
	socklen_t optlen = 0;
	optlen = sizeof(socktype);
	sa_family_t fam = SOCKFAMILY(*dest_addr);
	getsockopt(sockfd, SOL_SOCKET, SO_TYPE, &socktype, &optlen);
	if(!((fam  == AF_INET || fam == AF_INET6) && socktype == SOCK_DGRAM)){
		return true_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
	}

	// Here we have a SOCK_DRGAM socket with an AF_INET or AF_INET6 address
	ip_type dest_ip;
	struct in_addr *p_addr_in;
	struct in6_addr *p_addr_in6;
	dnat_arg *dnat = NULL;
	size_t i;
	int remote_dns_connect = 0;
	unsigned short port;
	int v6 = dest_ip.is_v6 = fam == AF_INET6;

	p_addr_in = &((struct sockaddr_in *) dest_addr)->sin_addr;
	p_addr_in6 = &((struct sockaddr_in6 *) dest_addr)->sin6_addr;
	port = !v6 ? ntohs(((struct sockaddr_in *) dest_addr)->sin_port)
	           : ntohs(((struct sockaddr_in6 *) dest_addr)->sin6_port);
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

	PDEBUG("target: %s\n", inet_ntop(v6 ? AF_INET6 : AF_INET, v6 ? (void*)p_addr_in6 : (void*)p_addr_in, str, sizeof(str)));
	PDEBUG("port: %d\n", port);
	PDEBUG("client socket: %d\n", sockfd);
	PDEBUG("trying to send %lu bytes : ", len);
	DUMP_BUFFER(buf, len);

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
		PDEBUG("accessing localnet using true_sendto\n");
		return true_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
	}

	// Check if a chain of UDP relay is already opened for this socket
	PDEBUG("waiting for mutex\n");
	MUTEX_LOCK(&relay_chains_mutex);
	PDEBUG("got mutex\n");
	udp_relay_chain* relay_chain = get_relay_chain(relay_chains, sockfd);
	if(relay_chain == NULL){
		// No chain is opened for this socket, open one
		PDEBUG("opening new chain of relays for %d\n", sockfd);
		if(NULL == (relay_chain = open_relay_chain(proxychains_pd, proxychains_proxy_count, proxychains_ct, proxychains_max_chain))){
			PDEBUG("could not open a chain of relay\n");
			errno = ECONNREFUSED;
			MUTEX_UNLOCK(&relay_chains_mutex);
			return -1;
		}
		relay_chain->sockfd = sockfd;
		add_relay_chain(&relay_chains, relay_chain);
		DUMP_RELAY_CHAINS_LIST(relay_chains);
	}
	

	memcpy(dest_ip.addr.v6, v6 ? (void*)p_addr_in6 : (void*)p_addr_in, v6?16:4);

	char send_buffer[65535];
	size_t send_buffer_len = sizeof(send_buffer);

	int rc;
	rc = socksify_udp_packet(buf, len, *relay_chain, dest_ip, htons(port), send_buffer, &send_buffer_len);
	if(rc != SUCCESS){
		PDEBUG("error socksify_udp_packet()\n");
		MUTEX_UNLOCK(&relay_chains_mutex);
		return -1;
	}

	// Send the packet
	// FIXME: should write_n_bytes be used here instead ? -> No, because we send data on an unconnected socket, so we need to use sendto with an address and not send.
	// We thus cannot use write(), which cannot be given an address

	// if(chain.head->bnd_addr.atyp == ATYP_DOM){
	// 	PDEBUG("BND_ADDR of type DOMAINE (0x03) not supported yet\n");
	// 	goto err;
	// }

	v6 = relay_chain->head->bnd_addr.is_v6;

	struct sockaddr_in addr = { 
		.sin_family = AF_INET,
		.sin_port = relay_chain->head->bnd_port,
		.sin_addr.s_addr = (in_addr_t) relay_chain->head->bnd_addr.addr.v4.as_int,
	};
	struct sockaddr_in6 addr6 = {
		.sin6_family = AF_INET6,
		.sin6_port = relay_chain->head->bnd_port,
	};
	if(v6) memcpy(&addr6.sin6_addr.s6_addr, relay_chain->head->bnd_addr.addr.v6, 16);


	//Drop the MSG_DONTROUTE flag if it exists
	if(flags & MSG_DONTROUTE){
		proxychains_write_log(LOG_PREFIX "dropping MSG_DONTROUTE flag\n");
		flags ^= MSG_DONTROUTE;
	}
	//Return EOPNOTSUPP if flag MSG_MORE is set 
	//TODO: implement MSG_MORE logic so that data from multiple sendto calls can be merged into one UDP datagram and sent to the SOCKS
	if(flags & MSG_MORE){
		PDEBUG("error, MSG_MORE not yet supported\n");
		errno = EOPNOTSUPP;
		MUTEX_UNLOCK(&relay_chains_mutex);
		return -1;
	}
	MUTEX_UNLOCK(&relay_chains_mutex);

	ssize_t sent = 0;
	sent = true_sendto(sockfd, send_buffer, send_buffer_len, flags, (struct sockaddr*)(v6?(void*)&addr6:(void*)&addr), v6?sizeof(addr6):sizeof(addr));

	if(sent == -1){
		PDEBUG("error true_sendto()\n");
		return sent;
	}

	PDEBUG("Successful sendto() hook\n\n");			
	return sent;
}

HOOKFUNC(ssize_t, sendmsg, int sockfd, const struct msghdr *msg, int flags){
	INIT();
	PFUNC();

	//TODO : do we keep this FASTOPEN code from sendto() ?
	// if (flags & MSG_FASTOPEN) {
	// 	if (!connect(sockfd, dest_addr, addrlen) && errno != EINPROGRESS) {
	// 		return -1;
	// 	}
	// 	dest_addr = NULL;
	// 	addrlen = 0;
	// 	flags &= ~MSG_FASTOPEN;

	// 	return true_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
	// }

	//TODO hugoc: case of SOCK_DGRAM with AF_INET or AF_INET6

	//TODO: check what to do when a UDP socket has been "connected" before and then sendmsg is called with msg->msg_name = NULL ?  

	struct sockaddr_storage dest_addr;
	socklen_t addrlen = sizeof(dest_addr);

	if(msg->msg_name == NULL){ // try to find a peer addr that could have been set with connect()
		int rc = 0;
		rc = getpeername(sockfd, (struct sockaddr*)&dest_addr, &addrlen);
		if(rc != SUCCESS){
			PDEBUG("error in getpeername(): %d\n", errno);
			return -1;
		}
	} else {
		if(msg->msg_namelen > addrlen){
			PDEBUG("msg->msg_name too long\n");
			return -1;
		}
		addrlen = msg->msg_namelen;
		memcpy(&dest_addr, msg->msg_name, addrlen);
	}
	


	DEBUGDECL(char str[256]);
	int socktype = 0, ret = 0;
	socklen_t optlen = 0;
	optlen = sizeof(socktype);
	sa_family_t fam = SOCKFAMILY(dest_addr);
	getsockopt(sockfd, SOL_SOCKET, SO_TYPE, &socktype, &optlen);
	if(!((fam  == AF_INET || fam == AF_INET6) && socktype == SOCK_DGRAM)){
		return true_sendmsg(sockfd, msg, flags);
	}

	PDEBUG("before send dump : ");
	DUMP_BUFFER(&dest_addr, addrlen);
	
	ip_type dest_ip;
	struct in_addr *p_addr_in;
	struct in6_addr *p_addr_in6;
	dnat_arg *dnat = NULL;
	size_t i;
	int remote_dns_connect = 0;
	unsigned short port;
	int v6 = dest_ip.is_v6 = fam == AF_INET6;

	p_addr_in = &((struct sockaddr_in *) &dest_addr)->sin_addr;
	p_addr_in6 = &((struct 
	sockaddr_in6 *) &dest_addr)->sin6_addr;
	port = !v6 ? ntohs(((struct sockaddr_in *) &dest_addr)->sin_port)
	           : ntohs(((struct sockaddr_in6 *) &dest_addr)->sin6_port);
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

	PDEBUG("target: %s\n", inet_ntop(v6 ? AF_INET6 : AF_INET, v6 ? (void*)p_addr_in6 : (void*)p_addr_in, str, sizeof(str)));
	PDEBUG("port: %d\n", port);
	PDEBUG("client socket: %d\n", sockfd);

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
		PDEBUG("accessing localnet using true_sendmsg\n");
		return true_sendmsg(sockfd, msg, flags);
	}

	// Check if a chain of UDP relay is already opened for this socket
	PDEBUG("waiting for mutex\n");
	MUTEX_LOCK(&relay_chains_mutex);
	PDEBUG("got mutex\n");
	udp_relay_chain* relay_chain = get_relay_chain(relay_chains, sockfd);
	if(relay_chain == NULL){
		// No chain is opened for this socket, open one
		PDEBUG("opening new chain of relays for %d\n", sockfd);
		if(NULL == (relay_chain = open_relay_chain(proxychains_pd, proxychains_proxy_count, proxychains_ct, proxychains_max_chain))){
			PDEBUG("could not open a chain of relay\n");
			errno = ECONNREFUSED;
			MUTEX_UNLOCK(&relay_chains_mutex);
			return -1;
		}
		relay_chain->sockfd = sockfd;
		add_relay_chain(&relay_chains, relay_chain);
		DUMP_RELAY_CHAINS_LIST(relay_chains);
	}
	

	memcpy(dest_ip.addr.v6, v6 ? (void*)p_addr_in6 : (void*)p_addr_in, v6?16:4);


	// Allocate buffer for header creation
	char send_buffer[65535]; //TODO maybe we can do better about size ? 
	size_t send_buffer_len = 65535;

	//Move iovec udp data contained in msg to one buffer
	char udp_data[65535];
	size_t udp_data_len = 65535;
	udp_data_len = write_iov_to_buf(udp_data, udp_data_len, msg->msg_iov, msg->msg_iovlen);

	// Exec socksify_udp_packet 
	int rc;
	rc = socksify_udp_packet(udp_data, udp_data_len, *relay_chain, dest_ip, htons(port),send_buffer, &send_buffer_len);
	if(rc != SUCCESS){
		PDEBUG("error socksify_udp_packet()\n");
		MUTEX_UNLOCK(&relay_chains_mutex);
		return -1;
	}


	// send with true_sendmsg()
	//prepare our msg
	struct iovec iov[1];
	iov[0].iov_base = send_buffer;
	iov[0].iov_len = send_buffer_len;


	struct msghdr tmp_msg;
	tmp_msg.msg_control = msg->msg_control;
	tmp_msg.msg_controllen = msg->msg_controllen;
	tmp_msg.msg_flags = msg->msg_flags;
	tmp_msg.msg_iov = iov;
	tmp_msg.msg_iovlen = 1;
	
	v6 = relay_chain->head->bnd_addr.is_v6 == ATYP_V6;
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = relay_chain->head->bnd_port,
		.sin_addr.s_addr = (in_addr_t) relay_chain->head->bnd_addr.addr.v4.as_int,
	};
	struct sockaddr_in6 addr6 = {
		.sin6_family = AF_INET6,
		.sin6_port = relay_chain->head->bnd_port,
	};
	if(v6) memcpy(&addr6.sin6_addr.s6_addr, relay_chain->head->bnd_addr.addr.v6, 16);

	

	tmp_msg.msg_name = (struct sockaddr*)(v6?(void*)&addr6:(void*)&addr);
	tmp_msg.msg_namelen = v6?sizeof(addr6):sizeof(addr) ;
	
	MUTEX_UNLOCK(&relay_chains_mutex);
	
	//send it

	//Drop the MSG_DONTROUTE flag if it exists
	if(flags & MSG_DONTROUTE){
		proxychains_write_log(LOG_PREFIX "dropping MSG_DONTROUTE flag\n");
		flags ^= MSG_DONTROUTE;
	}
	//Return EOPNOTSUPP if flag MSG_MORE is set 
	//TODO: implement MSG_MORE logic so that data from multiple sendto calls can be merged into one UDP datagram and sent to the SOCKS
	if(flags & MSG_MORE){
		PDEBUG("error, MSG_MORE not yet supported\n");
		errno = EOPNOTSUPP;
		return -1;
	}

	int sent = 0;
	sent = true_sendmsg(sockfd, &tmp_msg, flags);
	if(-1 == sent){
		PDEBUG("error true_sendmsg\n");
		return -1;
	}
	PDEBUG("Successfully sent UDP packet with true_sendmsg()\n");

	PDEBUG("Successful sendmsg() hook\n\n");
	return sent;
}

HOOKFUNC(int, sendmmsg, int sockfd, struct mmsghdr* msgvec, unsigned int vlen, int flags){

	PFUNC();
	int nmsg = -1; // The sendmmsg return code (-1 if error, otherwise number of messages sent)
	int allocated_len = 0; // A counter for dynamic memory allocations, used in freeAndExit section

	// As the call contains multiple message, we only filter on the first one address type :)

	struct sockaddr_storage first_dest_addr;
	socklen_t first_addrlen = sizeof(first_dest_addr);

	if(msgvec[0].msg_hdr.msg_name == NULL){ // try to find a peer addr that could have been set with connect()
		int rc = 0;
		rc = getpeername(sockfd, (struct sockaddr*)&first_dest_addr, &first_addrlen);
		if(rc != SUCCESS){
			PDEBUG("error in getpeername(): %d\n", errno);
			goto freeAndExit;
		}
	} else {
		if(msgvec[0].msg_hdr.msg_namelen > first_addrlen){
			PDEBUG("msgvec[0].msg_hdr.msg_namelen too long\n");
			return -1;
		}
		first_addrlen = msgvec[0].msg_hdr.msg_namelen;
		memcpy(&first_dest_addr, msgvec[0].msg_hdr.msg_name, first_addrlen);
	}
	


	DEBUGDECL(char str[256]);
	int socktype = 0, ret = 0;
	socklen_t optlen = 0;
	optlen = sizeof(socktype);
	sa_family_t fam = SOCKFAMILY(first_dest_addr);
	getsockopt(sockfd, SOL_SOCKET, SO_TYPE, &socktype, &optlen);
	if(!((fam  == AF_INET || fam == AF_INET6) && socktype == SOCK_DGRAM)){
		nmsg = true_sendmmsg(sockfd, msgvec, vlen, flags);
		goto freeAndExit;
	}

	// Check if a chain of UDP relay is already opened for this socket
	PDEBUG("waiting for mutex\n");
	MUTEX_LOCK(&relay_chains_mutex);
	PDEBUG("got mutex\n");
	udp_relay_chain* relay_chain = get_relay_chain(relay_chains, sockfd);
	if(relay_chain == NULL){
		// No chain is opened for this socket, open one
		PDEBUG("opening new chain of relays for %d\n", sockfd);
		if(NULL == (relay_chain = open_relay_chain(proxychains_pd, proxychains_proxy_count, proxychains_ct, proxychains_max_chain))){
			PDEBUG("could not open a chain of relay\n");
			errno = ECONNREFUSED;
			MUTEX_UNLOCK(&relay_chains_mutex);
			goto freeAndExit;
		}
		relay_chain->sockfd = sockfd;
		add_relay_chain(&relay_chains, relay_chain);
		DUMP_RELAY_CHAINS_LIST(relay_chains);

	}
	

	// Prepare our mmsg
	struct mmsghdr* tmp_msgvec = NULL;
	if(NULL == (tmp_msgvec = (struct mmsghdr*)calloc(vlen, sizeof(struct mmsghdr)))){
		PDEBUG("error allocating memory for tmp_mmsghdr\n");
		MUTEX_UNLOCK(&relay_chains_mutex);
		goto freeAndExit;
	}



	for(int msg_index=0; msg_index<vlen; msg_index++){ // Go through each individual mmsghdr of msgvec

		// Declare pointers for dynamicly allocated memory
		char* send_buffer = NULL;
		struct iovec* iov = NULL;
		struct sockaddr_in* pAddr = NULL;
		struct sockaddr_in6* pAddr6 = NULL;



		struct sockaddr_storage dest_addr;
		socklen_t addrlen = sizeof(dest_addr);

		if(msgvec[msg_index].msg_hdr.msg_name == NULL){ // try to find a peer addr that could have been set with connect()

			// WARNING: We assume that if the sendmmsg contains a message with a NULL destination address, then all
			// messages have a NULL destination address and we use the peer the socket is connected to (with a previous connect() call)
			// as the destination. Thus, we assume that if we encounter a NULL address here in the code, then msgvec[0].msg_hdr.msg_name == NULL
			// and the connected peer address was retrieved in the first call to getpeername at the very beginning of the sendmmsg hook.
			// This allows removing getpeername() calls from this for loop and avoid deadlocks on relay_chains_mutex


			// int rc = 0;
			// rc = getpeername(sockfd, (struct sockaddr*)&dest_addr, &addrlen);
			// if(rc != SUCCESS){
			// 	PDEBUG("error in getpeername(): %d\n", errno);
			// 	goto cleanCurrentLoop;
			// }

			// We then use first_dest_addr for dest_addr. It should contain the address retrieved with getpeername(), or otherwise (but it should not happen),
			// the content of msgvec[0].msg_hdr.msg_name

			
			memcpy(&dest_addr, &first_dest_addr, first_addrlen);

		} else {
			if(msgvec[msg_index].msg_hdr.msg_namelen > addrlen){
				PDEBUG("msgvec[%d].msg_hdr.msg_namelen too long\n", msg_index);
				MUTEX_UNLOCK(&relay_chains_mutex);
				return -1;
			}
			addrlen = msgvec[msg_index].msg_hdr.msg_namelen;
			memcpy(&dest_addr, msgvec[msg_index].msg_hdr.msg_name, addrlen);
		}

		ip_type dest_ip;
		struct in_addr *p_addr_in;
		struct in6_addr *p_addr_in6;
		dnat_arg *dnat = NULL;
		size_t i;
		int remote_dns_connect = 0;
		unsigned short port;
		int v6 = dest_ip.is_v6 = fam == AF_INET6;

		p_addr_in = &((struct sockaddr_in *) &dest_addr)->sin_addr;
		p_addr_in6 = &((struct 
		sockaddr_in6 *) &dest_addr)->sin6_addr;
		port = !v6 ? ntohs(((struct sockaddr_in *) &dest_addr)->sin_port)
				: ntohs(((struct sockaddr_in6 *) &dest_addr)->sin6_port);
		struct in_addr v4inv6;
		if(v6 && is_v4inv6(p_addr_in6)) {
			memcpy(&v4inv6.s_addr, &p_addr_in6->s6_addr[12], 4);
			v6 = dest_ip.is_v6 = 0;
			p_addr_in = &v4inv6;
		}
		if(!v6 && !memcmp(p_addr_in, "\0\0\0\0", 4)) {
			errno = ECONNREFUSED;
			goto cleanCurrentLoop;
		}

		PDEBUG("message %d/%d\n", msg_index+1, vlen);
		PDEBUG("target: %s\n", inet_ntop(v6 ? AF_INET6 : AF_INET, v6 ? (void*)p_addr_in6 : (void*)p_addr_in, str, sizeof(str)));
		PDEBUG("port: %d\n", port);
		PDEBUG("client socket: %d\n", sockfd);		

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
			PDEBUG("message %d/%d is accessing localnet\n", msg_index, vlen);
			goto cleanCurrentLoop;
		}

		memcpy(dest_ip.addr.v6, v6 ? (void*)p_addr_in6 : (void*)p_addr_in, v6?16:4);

		// Allocate buffer for header creation
		
		if(NULL == (send_buffer = (char*)malloc(65535))){
			PDEBUG("error malloc\n");
			goto cleanCurrentLoop;
		}
		size_t send_buffer_len = 65535;

		//Move iovec udp data contained in msg to one buffer
		char udp_data[65535];
		size_t udp_data_len = 65535;

		udp_data_len = write_iov_to_buf(udp_data, udp_data_len,msgvec[msg_index].msg_hdr.msg_iov ,msgvec[msg_index].msg_hdr.msg_iovlen);

		// Exec socksify_udp_packet 
		int rc;
		rc = socksify_udp_packet(udp_data, udp_data_len, *relay_chain, dest_ip, htons(port),send_buffer, &send_buffer_len);
		if(rc != SUCCESS){
			PDEBUG("error socksify_udp_packet()\n");
			goto cleanCurrentLoop;
		}

		//prepare our msg
		
		if(NULL == (iov = (struct iovec*)calloc(1, sizeof(struct iovec)))){
			PDEBUG("error calloc\n");
			goto cleanCurrentLoop;
		}
		iov->iov_base = send_buffer;
		iov->iov_len = send_buffer_len;


		
		tmp_msgvec[msg_index].msg_hdr.msg_control = msgvec[msg_index].msg_hdr.msg_control;
		tmp_msgvec[msg_index].msg_hdr.msg_controllen = msgvec[msg_index].msg_hdr.msg_controllen;
		tmp_msgvec[msg_index].msg_hdr.msg_flags = msgvec[msg_index].msg_hdr.msg_flags;

		tmp_msgvec[msg_index].msg_hdr.msg_iov = iov;
		tmp_msgvec[msg_index].msg_hdr.msg_iovlen = 1;
		
		v6 = relay_chain->head->bnd_addr.is_v6 == ATYP_V6;

		if(!v6){
			
			if(NULL == (pAddr = (struct sockaddr_in*)malloc(sizeof(struct sockaddr_in)))){
				PDEBUG("error malloc\n");
				goto cleanCurrentLoop;
			}
			pAddr->sin_family = AF_INET;
			pAddr->sin_port = relay_chain->head->bnd_port;
			pAddr->sin_addr.s_addr = (in_addr_t) relay_chain->head->bnd_addr.addr.v4.as_int;

			tmp_msgvec[msg_index].msg_hdr.msg_name = (struct sockaddr*)pAddr;
			tmp_msgvec[msg_index].msg_hdr.msg_namelen = sizeof(*pAddr) ;
		} else{
			
			if(NULL == (pAddr6 = (struct sockaddr_in6*)malloc(sizeof(struct sockaddr_in6)))){
				PDEBUG("error malloc\n");
				goto cleanCurrentLoop;
			}
			pAddr6->sin6_family = AF_INET6;
			pAddr6->sin6_port = relay_chain->head->bnd_port;
			if(v6) memcpy(pAddr6->sin6_addr.s6_addr, relay_chain->head->bnd_addr.addr.v6, 16);

			tmp_msgvec[msg_index].msg_hdr.msg_name = (struct sockaddr*)pAddr6;
			tmp_msgvec[msg_index].msg_hdr.msg_namelen = sizeof(*pAddr6);
		}
		
		allocated_len += 1;
		continue;

	cleanCurrentLoop:
		if(send_buffer != NULL){
			free(send_buffer);
		}
		if(iov != NULL){
			free(iov);
		}
		if(pAddr != NULL){
			free(pAddr);
		}
		if(pAddr6 != NULL){
			free(pAddr6);
		}
		MUTEX_UNLOCK(&relay_chains_mutex);
		goto freeAndExit;
	}
	
	MUTEX_UNLOCK(&relay_chains_mutex);

	//Drop the MSG_DONTROUTE flag if it exists
	if(flags & MSG_DONTROUTE){
		proxychains_write_log(LOG_PREFIX "dropping MSG_DONTROUTE flag\n");
		flags ^= MSG_DONTROUTE;
	}
	//Return EOPNOTSUPP if flag MSG_MORE is set 
	//TODO: implement MSG_MORE logic so that data from multiple sendto calls can be merged into one UDP datagram and sent to the SOCKS
	if(flags & MSG_MORE){
		PDEBUG("error, MSG_MORE not yet supported\n");
		errno = EOPNOTSUPP;
		return -1;
	}

	nmsg = true_sendmmsg(sockfd, tmp_msgvec, vlen, flags);

	if(nmsg == -1){
		PDEBUG("error true_sendmmsg: %d - %s\n", errno, strerror(errno) );
		goto freeAndExit;
	}

	// Update msg_len values of msgvec for the nmsg sent messages
	for(int i=0; i<nmsg; i++){
		msgvec[i].msg_len = tmp_msgvec[i].msg_len;
	}

	PDEBUG("Successfully sent %d UDP packets with true_sendmmsg()\n", nmsg);
	PDEBUG("Successful sendmmsg() hook\n\n");
	
freeAndExit:

	// Free memory allocated for tmp_msgvec contents
	for(int i=0; i<allocated_len; i++){
		free(tmp_msgvec[i].msg_hdr.msg_name);
		free(tmp_msgvec[i].msg_hdr.msg_iov->iov_base);
		free(tmp_msgvec[i].msg_hdr.msg_iov);
	}
	if(NULL != tmp_msgvec){
		free(tmp_msgvec);
	}

	return nmsg;
}

HOOKFUNC(ssize_t, recvmsg, int sockfd, struct msghdr *msg, int flags){


	INIT();
	PFUNC();

	int socktype = 0;
	socklen_t optlen = 0;
	optlen = sizeof(socktype);
	getsockopt(sockfd, SOL_SOCKET, SO_TYPE, &socktype, &optlen);
	if( socktype != SOCK_DGRAM){
		PDEBUG("sockfd %d is not a SOCK_DGRAM socket, returning to true_recvmsg\n", sockfd);
		return true_recvmsg(sockfd, msg, flags);
	}
	PDEBUG("sockfd %d is a SOCK_DGRAM socket\n", sockfd);

	struct sockaddr_storage addr;
	socklen_t addr_len = sizeof(addr);
	if(SUCCESS != getsockname(sockfd, (struct sockaddr*)&addr, &addr_len )){
		PDEBUG("error getsockname, errno=%d. Returning to true_recvmsg()\n", errno);
		return true_recvmsg(sockfd,msg, flags);
	}
	sa_family_t fam = SOCKFAMILY(addr);
	if(!(fam  == AF_INET || fam == AF_INET6)){
		PDEBUG("sockfd %d address familiy is not a AF_INET or AF_INET6, returning to true_recvmsg\n", sockfd);
		return true_recvmsg(sockfd,msg, flags);
	}

	PDEBUG("sockfd %d's address family is AF_INET or AF_INET6\n", sockfd);

	PDEBUG("waiting for mutex\n");
	MUTEX_LOCK(&relay_chains_mutex);
	PDEBUG("got mutex\n");
	udp_relay_chain* relay_chain = get_relay_chain(relay_chains, sockfd);
	if(relay_chain == NULL){
		// No chain is opened for this socket
		PDEBUG("sockfd %d does not corresponds to any opened relay chain, returning to true_recvmsg\n", sockfd);
		MUTEX_UNLOCK(&relay_chains_mutex);
		return true_recvmsg(sockfd,msg, flags);
	}	
	PDEBUG("sockfd %d is associated with udp_relay_chain %x\n", sockfd, relay_chain);


	char buffer[RECV_BUFFER_SIZE]; //buffer to receive and decapsulate a UDP relay packet
	size_t bytes_received;

	int trunc = flags & MSG_TRUNC;

	struct sockaddr_storage from;



	struct iovec iov[1];
	iov[0].iov_base = buffer;
	iov[0].iov_len = sizeof(buffer);


	struct msghdr tmp_msg;

	tmp_msg.msg_name = (void *)&from;
	tmp_msg.msg_namelen = sizeof(from);
	tmp_msg.msg_iov = iov;
	tmp_msg.msg_iovlen = 1;
	tmp_msg.msg_control = msg->msg_control; // Pass directly
	tmp_msg.msg_controllen = msg->msg_controllen; // Pass directly
	tmp_msg.msg_flags = msg->msg_flags;

	PDEBUG("exec true_recvmsg\n");
	bytes_received = true_recvmsg(sockfd, &tmp_msg, flags);
	if(-1 == bytes_received){
		PDEBUG("true_recvmsg returned -1, errno: %d, %s\n", errno,strerror(errno));
		MUTEX_UNLOCK(&relay_chains_mutex);
		return -1;
	}
	if(RECV_BUFFER_SIZE == bytes_received){
		PDEBUG("UDP PACKET SHOULD NOT BE THAT BIG\n");
	}

	// Transfer the fields we do not manage

	msg->msg_controllen = tmp_msg.msg_controllen;
	msg->msg_control = tmp_msg.msg_control; //Not sure this one is necessary 
	msg->msg_flags = tmp_msg.msg_flags;

	PDEBUG("successful recvmsg(), %d bytes received\n", bytes_received);
	//Check that the packet was received from the first relay of the chain
	DUMP_BUFFER(tmp_msg.msg_name, tmp_msg.msg_namelen);
	DUMP_BUFFER(relay_chain->head->bnd_addr.addr.v4.octet, 4);
	if(!is_from_chain_head(*relay_chain, (struct sockaddr *)(tmp_msg.msg_name))){
		PDEBUG("UDP packet not received from the proxy chain's head, transfering it as is\n");
		// Write the data we received in tmp_msg to msg
		int written = write_buf_to_iov(buffer, bytes_received, msg->msg_iov, msg->msg_iovlen);

		// Write the addr we received in tmp_msg to msg	
	    if(msg->msg_name != NULL){
			socklen_t min = (msg->msg_namelen>tmp_msg.msg_namelen)?tmp_msg.msg_namelen:msg->msg_namelen;
			memcpy(msg->msg_name, tmp_msg.msg_name, min);
			msg->msg_namelen = min;
		}
		MUTEX_UNLOCK(&relay_chains_mutex);
		return trunc?bytes_received:written; //if MSG_TRUNC flag is set, return the real length of the packet/datagram even when it was longer than the passed buffer (msg->msg_iov)
	}

	PDEBUG("packet received from the proxy chain's head\n");


	int rc;
	ip_type src_ip;
	unsigned short src_port;
	void* udp_data = NULL;
	size_t udp_data_len = 0;

	rc = unsocksify_udp_packet(buffer, bytes_received, *relay_chain, &src_ip, &src_port, &udp_data);
	MUTEX_UNLOCK(&relay_chains_mutex);
	if(rc != SUCCESS){
		PDEBUG("error unSOCKSing the UDP packet\n");
		return -1;
	}
	PDEBUG("UDP packet successfully unSOCKified\n");
	udp_data_len = bytes_received - (udp_data - (void*)buffer);

	/*debug*/
	DEBUGDECL(char str[256]);
	PDEBUG("received %d bytes through receive_udp_packet()\n", udp_data_len);
	PDEBUG("data: ");
	DUMP_BUFFER(udp_data, udp_data_len);
	PDEBUG("src_ip: ");
	DUMP_BUFFER(src_ip.addr.v6, src_ip.is_v6?16:4);
	PDEBUG("src_ip: %s\n", inet_ntop(src_ip.is_v6 ? AF_INET6 : AF_INET, src_ip.is_v6 ? (void*)src_ip.addr.v6 : (void*)src_ip.addr.v4.octet, str, sizeof(str)));
	PDEBUG("from_port: %hu\n", ntohs(src_port));
	/*end debug*/

	
	// Write the udp data we received in tmp_msg and unsocksified to msg
	int written = write_buf_to_iov(udp_data, udp_data_len, msg->msg_iov, msg->msg_iovlen);

	// Overwrite the addresse in msg with the src_addr retrieved from unsocks_udp_packet();
	
	if(msg->msg_name != NULL){
		struct sockaddr_in* src_addr_v4;
		struct sockaddr_in6* src_addr_v6;

		//TODO bien gérer le controle de la taille de la src_addr fournie et le retour dans addrlen
		// TODO faire une fonction cast_iptype_to_sockaddr() 

		if(src_ip.is_v6 && is_v4inv6((struct in6_addr*)src_ip.addr.v6)){
			PDEBUG("src_ip is v4 in v6 ip\n");
			if(msg->msg_namelen < sizeof(struct sockaddr_in)){
				PDEBUG("msg_namelen too short for ipv4\n");
			}
			src_addr_v4 = (struct sockaddr_in*)(msg->msg_name);
			src_addr_v4->sin_family = AF_INET;
			src_addr_v4->sin_port = src_port;
			memcpy(&(src_addr_v4->sin_addr.s_addr), src_ip.addr.v6+12, 4);
			msg->msg_namelen = sizeof(struct sockaddr_in);
		}
		else if(src_ip.is_v6){
			PDEBUG("src_ip is true v6\n");
			if(msg->msg_namelen < sizeof(struct sockaddr_in6)){
				PDEBUG("addrlen too short for ipv6\n");
				return -1;
			}
			src_addr_v6 = (struct sockaddr_in6*)(msg->msg_name);
			src_addr_v6->sin6_family = AF_INET6;
			src_addr_v6->sin6_port = src_port;
			memcpy(src_addr_v6->sin6_addr.s6_addr, src_ip.addr.v6, 16);
			msg->msg_namelen = sizeof(struct sockaddr_in6);
		}else {
			if(msg->msg_namelen < sizeof(struct sockaddr_in)){
				PDEBUG("addrlen too short for ipv4\n");
			}
			src_addr_v4 = (struct sockaddr_in*)(msg->msg_name);
			src_addr_v4->sin_family = AF_INET;
			src_addr_v4->sin_port = src_port;
			src_addr_v4->sin_addr.s_addr = (in_addr_t) src_ip.addr.v4.as_int;
			msg->msg_namelen = sizeof(struct sockaddr_in);
		} 
	}
	PDEBUG("after recv dump : ");
	DUMP_BUFFER(msg->msg_name, msg->msg_namelen);
	

	PDEBUG("Successful recvmsg() hook\n\n");
	return trunc?udp_data_len:written;//if MSG_TRUNC flag is set, return the real length of the packet/datagram even when it was longer than the passed buffer (msg->msg_iov)
}




HOOKFUNC(ssize_t, recv, int sockfd, void *buf, size_t len, int flags){
	INIT();
	PFUNC();
	
	return recvfrom(sockfd, buf, len, flags, NULL, NULL);
}

HOOKFUNC(ssize_t, recvfrom, int sockfd, void *buf, size_t len, int flags, 
			struct sockaddr *src_addr, socklen_t *addrlen){
	INIT();
	PFUNC();
	//TODO hugoc
	DEBUGDECL(char str[256]);
	int socktype = 0;
	socklen_t optlen = 0;
	optlen = sizeof(socktype);
	getsockopt(sockfd, SOL_SOCKET, SO_TYPE, &socktype, &optlen);
	if( socktype != SOCK_DGRAM){
		PDEBUG("sockfd %d is not a SOCK_DGRAM socket, returning to true_recvfrom\n", sockfd);
		return true_recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
	}
	PDEBUG("sockfd %d is a SOCK_DGRAM socket\n", sockfd);

	struct sockaddr_storage addr;
	socklen_t addr_len = sizeof(addr);
	if(SUCCESS != getsockname(sockfd, (struct sockaddr*)&addr, &addr_len )){
		PDEBUG("error getsockname, errno=%d. Returning to true_recvfrom()\n", errno);
		return true_recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
	}
	sa_family_t fam = SOCKFAMILY(addr);
	if(!(fam  == AF_INET || fam == AF_INET6)){
		PDEBUG("sockfd %d address familiy is not a AF_INET or AF_INET6, returning to true_recvfrom\n", sockfd);
		return true_recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
	}

	PDEBUG("sockfd %d's address family is AF_INET or AF_INET6\n", sockfd);

	PDEBUG("waiting for mutex\n");
	MUTEX_LOCK(&relay_chains_mutex);
	PDEBUG("got mutex\n");
	udp_relay_chain* relay_chain = get_relay_chain(relay_chains, sockfd);
	if(relay_chain == NULL){
		// No chain is opened for this socket
		PDEBUG("sockfd %d does not corresponds to any opened relay chain, returning to true_recvfrom\n", sockfd);
		MUTEX_UNLOCK(&relay_chains_mutex);
		return true_recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
	}	
	PDEBUG("sockfd %d is associated with udp_relay_chain %x\n", sockfd, relay_chain);
	

	
	char buffer[RECV_BUFFER_SIZE]; //maximum theoretical size of a UDP packet. 
	int bytes_received;
	ip_type src_ip;
	unsigned short src_port;

	int trunc = flags & MSG_TRUNC;


	struct sockaddr_storage from;
	socklen_t from_len = sizeof(from);
	bytes_received = true_recvfrom(sockfd, buffer, sizeof(buffer), flags, (struct sockaddr*)&from, &from_len);
	if(-1 == bytes_received){
		PDEBUG("true_recvfrom returned -1\n");
		MUTEX_UNLOCK(&relay_chains_mutex);
		return -1;
	}
	if(RECV_BUFFER_SIZE == bytes_received){
		PDEBUG("UDP PACKET SHOULD NOT BE THAT BIG\n");
	}
	PDEBUG("successful recvfrom(), %d bytes received\n", bytes_received);
	PDEBUG("packet: ");
	DUMP_BUFFER(buffer, bytes_received);
	
	//Check that the packet was received from the first relay of the chain
	// i.e. does from == chain.head.bnd_addr ?

	if(!is_from_chain_head(*relay_chain, (struct sockaddr*)&from)){
		//TODO: Decide whether we should transfer such packets not coming from the proxy chain
		PDEBUG("UDP packet not received from the proxy chain's head, transfering it as is\n");
		int min = (bytes_received <= len)?bytes_received:len;
	
		memcpy(buf, buffer, min);
		if(src_addr != NULL){ //TODO: check that the address copy is done correctly
			socklen_t min_addr_len = (from_len<*addrlen)?from_len:*addrlen;
			memcpy(src_addr, &from, min_addr_len);
			*addrlen = min_addr_len;
		}
		MUTEX_UNLOCK(&relay_chains_mutex);
		return trunc?bytes_received:min; //if MSG_TRUNC flag is set, return the real length of the packet/datagram even when it was longer than the passed buffer (buf)
	}
	PDEBUG("packet received from the proxy chain's head\n");
	
	int rc;
	void* udp_data = NULL;
	size_t  udp_data_len = 0;
	rc = unsocksify_udp_packet(buffer, bytes_received, *relay_chain, &src_ip, &src_port, &udp_data);
	MUTEX_UNLOCK(&relay_chains_mutex);
	if(rc != SUCCESS){
		PDEBUG("error unsocksifying the UDP packet\n");
		return -1;
	}
	PDEBUG("UDP packet successfully unsocksifyied\n");
	udp_data_len = bytes_received - (udp_data - (void*)buffer);

	

	PDEBUG("received %d bytes through receive_udp_packet()\n", udp_data_len);
	PDEBUG("data: ");
	DUMP_BUFFER(udp_data, udp_data_len);
	PDEBUG("from_addr: ");
	DUMP_BUFFER(src_ip.addr.v6, src_ip.is_v6?16:4);
	PDEBUG("from_addr: %s\n", inet_ntop(src_ip.is_v6 ? AF_INET6 : AF_INET, src_ip.is_v6 ? (void*)src_ip.addr.v6 : (void*)src_ip.addr.v4.octet, str, sizeof(str)));
	PDEBUG("from_port: %hu\n", ntohs(src_port));

	// Copy received UDP data to the buffer provided by the client
	size_t min = (udp_data_len < len)?udp_data_len:len;
	memcpy(buf, udp_data, min);
	
	// WARNING : Est ce que si le client avait envoyé des packets UDP avec resolution DNS dans le socks,
	// on doit lui filer comme address source pour les packets recu l'addresse de mapping DNS ? Si oui comment
	// la retrouver ? -> done in unsocksify_udp_packet()
	


	if(src_addr != NULL){ // No need to fill src_addr if the passed pointer is NULL
		struct sockaddr_in* src_addr_v4;
		struct sockaddr_in6* src_addr_v6;

		//TODO bien gérer le controle de la taille de la src_addr fournie et le retour dans addrlen
		// 

		if(src_ip.is_v6 && is_v4inv6((struct in6_addr*)src_ip.addr.v6)){
			PDEBUG("src_ip is v4 in v6 ip\n");
			if(addrlen < sizeof(struct sockaddr_in)){
				PDEBUG("addrlen too short for ipv4\n");
			}
			src_addr_v4 = (struct sockaddr_in*)src_addr;
			src_addr_v4->sin_family = AF_INET;
			src_addr_v4->sin_port = src_port;
			memcpy(&(src_addr_v4->sin_addr.s_addr), src_ip.addr.v6+12, 4);
			*addrlen = sizeof(src_addr_v4);
		}
		else if(src_ip.is_v6){
			PDEBUG("src_ip is true v6\n");
			if(addrlen < sizeof(struct sockaddr_in6)){
				PDEBUG("addrlen too short for ipv6\n");
				return -1;
			}
			src_addr_v6 = (struct sockaddr_in6*)src_addr;
			src_addr_v6->sin6_family = AF_INET6;
			src_addr_v6->sin6_port = src_port;
			memcpy(src_addr_v6->sin6_addr.s6_addr, src_ip.addr.v6, 16);
			*addrlen = sizeof(src_addr_v6);
		}else {
			if(addrlen < sizeof(struct sockaddr_in)){
				PDEBUG("addrlen too short for  ipv4\n");
			}
			src_addr_v4 = (struct sockaddr_in*)src_addr;
			src_addr_v4->sin_family = AF_INET;
			src_addr_v4->sin_port = src_port;
			src_addr_v4->sin_addr.s_addr = (in_addr_t) src_ip.addr.v4.as_int;
			*addrlen = sizeof(src_addr_v4);
		}
	}

	PDEBUG("Successful recvfrom() hook\n\n");
	return trunc?udp_data_len:min; //if MSG_TRUNC flag is set, return the real length of the packet/datagram even when it was longer than the passed buffer (buf)
}

HOOKFUNC(ssize_t, send, int sockfd, const void *buf, size_t len, int flags){
	INIT();
	PFUNC();
	
	// Check if sockfd is a SOCK_DGRAM socket 

	int socktype = 0;
	socklen_t optlen = 0;
	optlen = sizeof(socktype);
	getsockopt(sockfd, SOL_SOCKET, SO_TYPE, &socktype, &optlen);
	if( socktype != SOCK_DGRAM){
		PDEBUG("sockfd %d is not a SOCK_DGRAM socket, returning to true_send\n", sockfd);
		return true_send(sockfd, buf, len, flags);
	}

	// Retreive the peer address the socket is connected to, and check it is of AF_INET or AF_INET6 family

	struct sockaddr_storage addr;
	socklen_t addr_len = sizeof(addr);
	if(SUCCESS != getpeername(sockfd, (struct sockaddr*)&addr, &addr_len )){
		PDEBUG("error getpeername, errno=%d. Returning to true_send()\n", errno);
		return true_send(sockfd, buf, len, flags);
	}

	sa_family_t fam = SOCKFAMILY(addr);
	if(!(fam  == AF_INET || fam == AF_INET6)){
		PDEBUG("sockfd %d address familiy is not a AF_INET or AF_INET6, returning to true_send\n", sockfd);
		return true_send(sockfd, buf, len, flags);
	}

	// Call the sendto() hook with the send() parameters and the retrieved peer address 
	return sendto(sockfd, buf, len, flags, (struct sockaddr*)&addr, addr_len);
}


HOOKFUNC(ssize_t, read,int fd, void* buf, size_t count){
	
	// If fd is a socket, call recv() with no flags as it is equivalent to read()
	// WARNING: As stated in https://man7.org/linux/man-pages/man2/recv.2.html in NOTES, 
	//"If a zero-length datagram is pending, read(2) and recv() with a
    // flags argument of zero provide different behavior.  In this
	// circumstance, read(2) has no effect (the datagram remains
	// pending), while recv() consumes the pending datagram."

	struct stat statbuf;
	fstat(fd, &statbuf);
	if(S_ISSOCK(statbuf.st_mode)){
		PDEBUG("hooked read() on a socket file descriptor, calling recv() with 0 flags\n");
		return recv(fd, buf, count, 0);
	}
	return true_read(fd, buf, count);
}

HOOKFUNC(ssize_t, write, int fd, const void* buf, size_t count ){


	// If fd is a socket, call send() with no flags as it is equivalent to write()
	struct stat statbuf;
	fstat(fd, &statbuf);
	if(S_ISSOCK(statbuf.st_mode)){
		PDEBUG("hooked write() on a socket file descriptor, calling send() with 0 flags\n");
		return send(fd, buf,count, 0);
	}
	return true_write(fd, buf, count);
}

#ifdef MONTEREY_HOOKING
#define SETUP_SYM(X) do { if (! true_ ## X ) true_ ## X = &X; } while(0)
#define SETUP_SYM_OPTIONAL(X)
#else
#define SETUP_SYM_IMPL(X, IS_MANDATORY) do { if (! true_ ## X ) true_ ## X = load_sym( # X, X, IS_MANDATORY ); } while(0)
#define SETUP_SYM(X) SETUP_SYM_IMPL(X, 1)
#define SETUP_SYM_OPTIONAL(X) SETUP_SYM_IMPL(X, 0)
#endif

static void setup_hooks(void) {
	SETUP_SYM(connect);
	SETUP_SYM(getpeername);
	SETUP_SYM(send);
	SETUP_SYM(sendto);
	SETUP_SYM(recvfrom);
	SETUP_SYM(recvmsg);
	SETUP_SYM(sendmsg);
	SETUP_SYM(sendmmsg);
	SETUP_SYM(recv);
	SETUP_SYM(gethostbyname);
	SETUP_SYM(getaddrinfo);
	SETUP_SYM(freeaddrinfo);
	SETUP_SYM(gethostbyaddr);
	SETUP_SYM(getnameinfo);
	SETUP_SYM(write);
	SETUP_SYM(read);
#ifdef IS_SOLARIS
	SETUP_SYM(__xnet_connect);
#endif
	SETUP_SYM(close);
	SETUP_SYM_OPTIONAL(close_range);
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
