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
#include <netdb.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <dlfcn.h>


#include "core.h"
#include "common.h"

#define     satosin(x)      ((struct sockaddr_in *) &(x))
#define     SOCKADDR(x)     (satosin(x)->sin_addr.s_addr)
#define     SOCKADDR_2(x)     (satosin(x)->sin_addr)
#define     SOCKPORT(x)     (satosin(x)->sin_port)
#define     SOCKFAMILY(x)     (satosin(x)->sin_family)
#define     MAX_CHAIN 30*1024

int tcp_read_time_out;
int tcp_connect_time_out;
chain_type proxychains_ct;
proxy_data proxychains_pd[MAX_CHAIN];
unsigned int proxychains_proxy_count = 0;
int proxychains_got_chain_data = 0;
unsigned int proxychains_max_chain = 1;
int proxychains_quiet_mode = 0;
int proxychains_resolver = 0;
static int init_l = 0;
localaddr_arg localnet_addr[MAX_LOCALNET];
size_t num_localnet_addr = 0;

static inline void get_chain_data(proxy_data *pd, unsigned int *proxy_count,
	chain_type *ct);
static void init_lib(void);

static void init_lib(void)
{
#ifdef THREAD_SAFE
	pthread_mutex_init(&internal_ips_lock, NULL);
#endif
	/* read the config file */
	get_chain_data(proxychains_pd, &proxychains_proxy_count, &proxychains_ct);
	
	proxychains_write_log(LOG_PREFIX "DLL init\n");
	
	true_connect = (connect_t) dlsym(RTLD_NEXT, "connect");

	if (!true_connect) {
		fprintf(stderr, "Cannot load symbol 'connect' %s\n", dlerror());
		exit(1);
	} else {
		#ifdef DEBUG
		PDEBUG( "loaded symbol 'connect'"
		" real addr %p  wrapped addr %p\n",
		true_connect, connect);
		#endif
	}
	if(connect==true_connect) {
		#ifdef DEBUG
		PDEBUG("circular reference detected, aborting!\n");
		#endif
		abort();
	}
	
	true_gethostbyname = (gethostbyname_t) 
		dlsym(RTLD_NEXT, "gethostbyname");

	if (!true_gethostbyname) {
		fprintf(stderr, "Cannot load symbol 'gethostbyname' %s\n", 
				dlerror());
		exit(1);
	} else {
		#ifdef DEBUG
		PDEBUG( "loaded symbol 'gethostbyname'"
		" real addr %p  wrapped addr %p\n",
		true_gethostbyname, gethostbyname);
		#endif
	}
	true_getaddrinfo = (getaddrinfo_t) 
		dlsym(RTLD_NEXT, "getaddrinfo");

	if (!true_getaddrinfo) {
		fprintf(stderr, "Cannot load symbol 'getaddrinfo' %s\n", 
				dlerror());
		exit(1);
	} else {
		#ifdef DEBUG
		PDEBUG( "loaded symbol 'getaddrinfo'"
			" real addr %p  wrapped addr %p\n",
			true_getaddrinfo, getaddrinfo);
		#endif
	}
	true_freeaddrinfo = (freeaddrinfo_t) 
		dlsym(RTLD_NEXT, "freeaddrinfo");

	if (!true_freeaddrinfo) {
		fprintf(stderr, "Cannot load symbol 'freeaddrinfo' %s\n", 
				dlerror());
		exit(1);
	} else {
		#ifdef DEBUG
		PDEBUG( "loaded symbol 'freeaddrinfo'"
			" real addr %p  wrapped addr %p\n",
			true_freeaddrinfo, freeaddrinfo);
		#endif
	}
	true_gethostbyaddr = (gethostbyaddr_t) 
		dlsym(RTLD_NEXT, "gethostbyaddr");

	if (!true_gethostbyaddr) {
		fprintf(stderr, "Cannot load symbol 'gethostbyaddr' %s\n", 
				dlerror());
		exit(1);
	} else {
		#ifdef DEBUG
		PDEBUG( "loaded symbol 'gethostbyaddr'"
			" real addr %p  wrapped addr %p\n",
			true_gethostbyaddr, gethostbyaddr);
		#endif
	}
	true_getnameinfo = (getnameinfo_t) 
		dlsym(RTLD_NEXT, "getnameinfo");

	if (!true_getnameinfo) {
		fprintf(stderr, "Cannot load symbol 'getnameinfo' %s\n", 
				dlerror());
		exit(1);
	} else {
		#ifdef DEBUG
		PDEBUG( "loaded symbol 'getnameinfo'"
			" real addr %p  wrapped addr %p\n",
			true_getnameinfo, getnameinfo);
		#endif
	}
	init_l = 1;
}

static inline void get_chain_data(
			proxy_data *pd,
			unsigned int *proxy_count,
			chain_type *ct)
{
	int count=0,port_n=0,list=0;
	char buff[1024],type[1024],host[1024],user[1024];
	char *env;
	char local_in_addr_port[32];
	char local_in_addr[32], local_in_port[32], local_netmask[32];
	FILE* file;

	if(proxychains_got_chain_data)
	return;

	//Some defaults
	tcp_read_time_out = 4*1000;
	tcp_connect_time_out = 10*1000;
	*ct = DYNAMIC_TYPE;

	/*
	 * Get path to configuration file from env this file has priority
	 * if it's defined.
	 */
	env = getenv(PROXYCHAINS_CONF_FILE_ENV_VAR);

	snprintf(buff,256,"%s/.proxychains/proxychains.conf",getenv("HOME"));

	if(!env || (!(file=fopen(env,"r"))))
	if(!(file=fopen("./proxychains.conf","r")))
	if(!(file=fopen(buff,"r")))
	if(!(file=fopen("/etc/proxychains.conf","r")))
	{
		perror("Can't locate proxychains.conf");
		exit(1);
	}
	
	env = getenv(PROXYCHAINS_QUIET_MODE_ENV_VAR);
	if(env && *env == '1') proxychains_quiet_mode = 1;

	while(fgets(buff,sizeof(buff),file)) {
		if(buff[0] != '\n' && buff[strspn(buff," ")]!='#') {
			if(list) {
				memset(&pd[count], 0, sizeof(proxy_data));
				
				pd[count].ps = PLAY_STATE;
				port_n = 0;
				
				sscanf(buff,"%s %s %d %s %s", type, host, &port_n,
					pd[count].user, pd[count].pass);
				
				pd[count].ip.as_int = (uint32_t) inet_addr(host);
				pd[count].port = htons((unsigned short)port_n);
				
				if(!strcmp(type,"http")) {
					pd[count].pt = HTTP_TYPE;
				} else if(!strcmp(type,"socks4")) {
					pd[count].pt = SOCKS4_TYPE;
				} else if(!strcmp(type,"socks5")) {
					pd[count].pt = SOCKS5_TYPE;
				} else 
					continue;
				
				if(pd[count].ip.as_int && port_n &&
				   pd[count].ip.as_int != (uint32_t) -1)
					if(++count==MAX_CHAIN)
						break;
			 } else {
				if(strstr(buff,"[ProxyList]")) {
					list=1;
				} else if(strstr(buff,"random_chain")) {
					*ct=RANDOM_TYPE;
				} else if(strstr(buff,"strict_chain")) {
					*ct=STRICT_TYPE;
				} else if(strstr(buff,"dynamic_chain")) {
					*ct=DYNAMIC_TYPE;
				} else if(strstr(buff,"tcp_read_time_out")){
					sscanf(buff,"%s %d",user,&tcp_read_time_out) ;
				} else if(strstr(buff,"tcp_connect_time_out")){
					sscanf(buff,"%s %d",user,&tcp_connect_time_out) ;
				} else if(strstr(buff,"localnet")) {
					if (sscanf(buff,"%s %21[^/]/%15s", user,
						local_in_addr_port, local_netmask) < 3) {
						fprintf(stderr, "localnet format error");
						exit(1);
					}
					/* clean previously used buffer */
					memset(local_in_port, 0,
						sizeof(local_in_port) / sizeof(local_in_port[0]));

					if (sscanf(local_in_addr_port, "%15[^:]:%5s",
						local_in_addr, local_in_port) < 2) {
					    PDEBUG("added localnet: netaddr=%s, port=%s\n",
							local_in_addr, local_netmask);
					} else {
					    PDEBUG("added localnet: netaddr=%s, port=%s, netmask=%s\n",
							local_in_addr, local_in_port, local_netmask);
					}
					if (num_localnet_addr < MAX_LOCALNET)
					{
						int error;
						error = inet_pton(AF_INET, local_in_addr, &localnet_addr[num_localnet_addr].in_addr);
						if (error <= 0)
						{
							fprintf(stderr, "localnet address error\n");
							exit(1);
						}
						error = inet_pton(AF_INET, local_netmask, &localnet_addr[num_localnet_addr].netmask);
						if (error <= 0)
						{
							fprintf(stderr, "localnet netmask error\n");
							exit(1);
						}
						if (local_in_port[0]) {
							localnet_addr[num_localnet_addr].port = (short)atoi(local_in_port);
						} else {
							localnet_addr[num_localnet_addr].port = 0;
						}
						++num_localnet_addr;
					}
					else
					{
						fprintf(stderr, "# of localnet exceed %d.\n", MAX_LOCALNET);
					}
				} else if(strstr(buff,"chain_len")){
					char *pc;int len;
					pc=strchr(buff,'=');
					len=atoi(++pc);
					proxychains_max_chain=(len?len:1);
				} else if(strstr(buff,"quiet_mode")){
					proxychains_quiet_mode=1;
				} else if(strstr(buff,"proxy_dns")){
					proxychains_resolver=1;
				}
			}
		}
	}
	fclose(file);
	*proxy_count = count;
	proxychains_got_chain_data = 1;
}



int connect (int sock, const struct sockaddr *addr, unsigned int len)
{
	int socktype=0, flags=0, ret=0;
	socklen_t optlen = 0;
	ip_type dest_ip;
#ifdef DEBUG
	char str[256];
#endif
	struct in_addr *p_addr_in;
	unsigned short port;
	size_t i;

	if(!init_l)
		init_lib();
	optlen=sizeof(socktype);
	getsockopt(sock,SOL_SOCKET,SO_TYPE,&socktype,&optlen);
	if (! (SOCKFAMILY(*addr)==AF_INET  && socktype==SOCK_STREAM))
		return true_connect(sock,addr,len);

	p_addr_in = &((struct sockaddr_in *)addr)->sin_addr;
	port = ntohs(((struct sockaddr_in *)addr)->sin_port);

#ifdef DEBUG
//	PDEBUG("localnet: %s; ", inet_ntop(AF_INET,&in_addr_localnet, str, sizeof(str)));
//	PDEBUG("netmask: %s; " , inet_ntop(AF_INET, &in_addr_netmask, str, sizeof(str)));
	PDEBUG("target: %s\n", inet_ntop(AF_INET, p_addr_in, str, sizeof(str)));
	PDEBUG("port: %d\n", port);
#endif
	for (i = 0; i < num_localnet_addr; i++) {
		if ((localnet_addr[i].in_addr.s_addr & localnet_addr[i].netmask.s_addr)
			== (p_addr_in->s_addr & localnet_addr[i].netmask.s_addr))
		{
			if (localnet_addr[i].port || localnet_addr[i].port == port) {
				PDEBUG("accessing localnet using true_connect\n");
				return true_connect(sock,addr,len);
			}
		}
	}

	flags = fcntl(sock, F_GETFL, 0);
	if(flags & O_NONBLOCK)
	fcntl(sock, F_SETFL, !O_NONBLOCK);
	
	dest_ip.as_int = SOCKADDR(*addr);
	
	ret = connect_proxy_chain(
		sock,
		dest_ip,
		SOCKPORT(*addr),
		proxychains_pd,
		proxychains_proxy_count,
		proxychains_ct,
		proxychains_max_chain );
	
	fcntl(sock, F_SETFL, flags);
	if(ret != SUCCESS)
	errno = ECONNREFUSED;
	return ret;
}

struct hostent *gethostbyname(const char *name)
{
	if(!init_l)
		init_lib();
	
	PDEBUG("gethostbyname: %s\n",name);
	
	if(proxychains_resolver)
		return proxy_gethostbyname(name);
	else
		return true_gethostbyname(name);
			
	return NULL;
}

int getaddrinfo(const char *node, const char *service,
		const struct addrinfo *hints,
		struct addrinfo **res)
{
	int ret = 0;
	
	if(!init_l)
		init_lib();
	
	PDEBUG("getaddrinfo: %s %s\n",node ,service);
	
	if(proxychains_resolver)
		ret = proxy_getaddrinfo(node, service, hints, res);
	else
		ret = true_getaddrinfo(node, service, hints, res);
			
	return ret;
}

void freeaddrinfo(struct addrinfo *res)
{
	if(!init_l)
		init_lib();
	
	PDEBUG("freeaddrinfo %p \n",res);
	
	if(!proxychains_resolver)
		true_freeaddrinfo(res);
	else {
		free(res->ai_addr);
		free(res);
	}
	return;
}
// work around a buggy prototype in GLIBC. according to the bugtracker it has been fixed in git at 02 May 2011.
// 2.14 came out in June 2011 so that should be the first fixed version
#if defined(__GLIBC__) && (__GLIBC__ < 3) && (__GLIBC_MINOR__ < 14)
int getnameinfo (const struct sockaddr * sa,
                        socklen_t salen, char * host,
                        socklen_t hostlen, char * serv,
                        socklen_t servlen, unsigned int flags)
#else
int getnameinfo (const struct sockaddr * sa,
			socklen_t salen, char * host,
			socklen_t hostlen, char * serv,
			socklen_t servlen, int flags)
#endif
{
	int ret = 0;
	
	if(!init_l)
		init_lib();
	
	PDEBUG("getnameinfo: %s %s\n", host, serv);
	
	if(!proxychains_resolver) {
		ret = true_getnameinfo(sa,salen,host,hostlen,
				serv,servlen,flags);
	} else {
		if(hostlen) 
			strncpy(host, inet_ntoa(SOCKADDR_2(*sa)),hostlen);
		if(servlen) 
			snprintf(serv, servlen,"%d",ntohs(SOCKPORT(*sa)));
	}
	return ret;
}

// stolen from libulz (C) rofl0r
static void pc_stringfromipv4(unsigned char* ip_buf_4_bytes, char* outbuf_16_bytes) {
        unsigned char* p;
        char *o = outbuf_16_bytes;
        unsigned char n;
        for(p = ip_buf_4_bytes; p < ip_buf_4_bytes + 4; p++) {
                n = *p;
                if(*p >= 100) {
                        if(*p >= 200) *(o++) = '2';
                        else *(o++) = '1';
                        n %= 100;
                }
                if(*p >= 10) {
                        *(o++) = (n / 10) + '0';
                        n %= 10;
                }
                *(o++) = n + '0';
                *(o++) = '.';
        }
        o[-1] = 0;
}

struct hostent *gethostbyaddr (const void *addr, socklen_t len, int type)
{
	static char buf[16];
	static char ipv4[4];
	static char* list[2];
	static struct hostent he;
	
	if(!init_l)
		init_lib();
	
	PDEBUG("TODO: proper gethostbyaddr hook\n");
	
	if(!proxychains_resolver)
		return true_gethostbyaddr(addr,len,type);
	else {
		
		PDEBUG("len %u\n", len);
		if(len != 4) return NULL;
		he.h_name = buf;
		memcpy(ipv4, addr, 4);
		list[0] = ipv4;
		list[1] = NULL;
		he.h_addr_list = list;
		he.h_addrtype = AF_INET;
		he.h_aliases = NULL;
		he.h_length = 4;
		pc_stringfromipv4((unsigned char*)addr, buf);
		return &he;
	}
	return NULL;
}
	
