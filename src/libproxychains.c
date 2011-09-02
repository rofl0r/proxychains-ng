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
#define _GNU_SOURCE
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
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
int proxychains_proxy_count = 0;
int proxychains_got_chain_data = 0;
int proxychains_max_chain = 1;
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
//	proxychains_write_log("ProxyChains-"VERSION
//			" (http://proxychains.sf.net)\n");
	
	get_chain_data(proxychains_pd,&proxychains_proxy_count,&proxychains_ct);
	true_connect = (connect_t) dlsym(RTLD_NEXT, "connect");

	if (!true_connect) {
		fprintf(stderr, "Cannot load symbol 'connect' %s\n", dlerror());
		exit(1);
	} else {
//		PDEBUG( "loaded symbol 'connect'"
//		" real addr %p  wrapped addr %p\n",
//		true_connect, connect);
	}
	true_gethostbyname = (gethostbyname_t) 
		dlsym(RTLD_NEXT, "gethostbyname");

	if (!true_gethostbyname) {
		fprintf(stderr, "Cannot load symbol 'gethostbyname' %s\n", 
				dlerror());
		exit(1);
	} else {
//		PDEBUG( "loaded symbol 'gethostbyname'"
//		" real addr %p  wrapped addr %p\n",
//		true_gethostbyname, gethostbyname);
	}
	true_getaddrinfo = (getaddrinfo_t) 
		dlsym(RTLD_NEXT, "getaddrinfo");

	if (!true_getaddrinfo) {
		fprintf(stderr, "Cannot load symbol 'getaddrinfo' %s\n", 
				dlerror());
		exit(1);
	} else {
//		PDEBUG( "loaded symbol 'getaddrinfo'"
//			" real addr %p  wrapped addr %p\n",
//			true_getaddrinfo, getaddrinfo);
	}
	true_freeaddrinfo = (freeaddrinfo_t) 
		dlsym(RTLD_NEXT, "freeaddrinfo");

	if (!true_freeaddrinfo) {
		fprintf(stderr, "Cannot load symbol 'freeaddrinfo' %s\n", 
				dlerror());
		exit(1);
	} else {
//		PDEBUG( "loaded symbol 'freeaddrinfo'"
//			" real addr %p  wrapped addr %p\n",
//			true_freeaddrinfo, freeaddrinfo);
	}
	true_gethostbyaddr = (gethostbyaddr_t) 
		dlsym(RTLD_NEXT, "gethostbyaddr");

	if (!true_gethostbyaddr) {
		fprintf(stderr, "Cannot load symbol 'gethostbyaddr' %s\n", 
				dlerror());
		exit(1);
	} else {
//		PDEBUG( "loaded symbol 'gethostbyaddr'"
//			" real addr %p  wrapped addr %p\n",
//			true_gethostbyaddr, gethostbyaddr);
	}
	true_getnameinfo = (getnameinfo_t) 
		dlsym(RTLD_NEXT, "getnameinfo");

	if (!true_getnameinfo) {
		fprintf(stderr, "Cannot load symbol 'getnameinfo' %s\n", 
				dlerror());
		exit(1);
	} else {
//		PDEBUG( "loaded symbol 'getnameinfo'"
//			" real addr %p  wrapped addr %p\n",
//			true_getnameinfo, getnameinfo);
	}
	init_l = 1;
}

/*
 * XXX. Same thing is defined in proxychains main.c it
 * needs to be changed, too.
 */
#define PROXYCHAINS_CONF_FILE "PROXYCHAINS_CONF_FILE"

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
	tcp_read_time_out=4*1000;
	tcp_connect_time_out=10*1000;
	*ct=DYNAMIC_TYPE;

	env = NULL;

	/*
	 * Get path to configuration file from env this file has priority
	 * if it's defined.
	 */
	env = getenv(PROXYCHAINS_CONF_FILE);

	snprintf(buff,256,"%s/.proxychains/proxychains.conf",getenv("HOME"));

	if(!(file=fopen(env,"r")))
	if(!(file=fopen("./proxychains.conf","r")))
	if(!(file=fopen(buff,"r")))
	if(!(file=fopen("/etc/proxychains.conf","r")))
	{
		perror("Can't locate proxychains.conf");
		exit(1);
	}

	while(fgets(buff,sizeof(buff),file)) {
		if(buff[strspn(buff," ")]!='#') {
			if(list) {
				memset(&pd[count], 0, sizeof(proxy_data));
				pd[count].ps=PLAY_STATE;
				port_n=0;
				sscanf(buff,"%s %s %d %s %s", type,host,&port_n,
					pd[count].user,pd[count].pass);
				pd[count].ip=inet_addr(host);
				pd[count].port=htons((unsigned short)port_n);
				if(!strcmp(type,"http")) {
					pd[count].pt=HTTP_TYPE;
				}else if(!strcmp(type,"socks4")) {
					pd[count].pt=SOCKS4_TYPE;
				}else if(!strcmp(type,"socks5")) {
					pd[count].pt=SOCKS5_TYPE;
				}else continue;
				
				if( pd[count].ip && pd[count].ip!=-1 && port_n)
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
				}else if(strstr(buff,"tcp_read_time_out")){
					sscanf(buff,"%s %d",user,&tcp_read_time_out) ;
				}else if(strstr(buff,"tcp_connect_time_out")){
					sscanf(buff,"%s %d",user,&tcp_connect_time_out) ;
				}
				else if(strstr(buff,"localnet"))
				{
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
				}
				else if(strstr(buff,"chain_len")){
					char *pc;int len;
					pc=strchr(buff,'=');
					len=atoi(++pc);
					proxychains_max_chain=(len?len:1);
				}else if(strstr(buff,"quiet_mode")){
					proxychains_quiet_mode=1;
				}else if(strstr(buff,"proxy_dns")){
					proxychains_resolver=1;
				}
			}
		}
	}
	fclose(file);
	*proxy_count=count;
	proxychains_got_chain_data=1;
}



int connect (int sock, const struct sockaddr *addr, unsigned int len)
{
	int socktype=0,optlen=0,flags=0,ret=0;
	char str[256];
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

	//PDEBUG("localnet: %s; ", inet_ntop(AF_INET,&in_addr_localnet, str, sizeof(str)));
	//PDEBUG("netmask: %s; " , inet_ntop(AF_INET, &in_addr_netmask, str, sizeof(str)));
	//PDEBUG("target: %s\n", inet_ntop(AF_INET, p_addr_in, str, sizeof(str)));
	//PDEBUG("port: %d\n", port);
	for (i = 0; i < num_localnet_addr; i++) {
		if ((localnet_addr[i].in_addr.s_addr & localnet_addr[i].netmask.s_addr)
			== (p_addr_in->s_addr & localnet_addr[i].netmask.s_addr))
		{
			if (localnet_addr[i].port && localnet_addr[i].port == port) {
				PDEBUG("accessing localnet using true_connect\n");
				return true_connect(sock,addr,len);
			}
		}
	}

	flags=fcntl(sock, F_GETFL, 0);
	if(flags & O_NONBLOCK)
	fcntl(sock, F_SETFL, !O_NONBLOCK);
	ret=connect_proxy_chain(
		sock,
		SOCKADDR(*addr),
		SOCKPORT(*addr),
		proxychains_pd,
		proxychains_proxy_count,
		proxychains_ct,
		  proxychains_max_chain );
	fcntl(sock, F_SETFL, flags);
	if(ret!=SUCCESS)
	errno=ECONNREFUSED;
	return ret;
}

struct hostent *gethostbyname(const char *name)
{
	PDEBUG("gethostbyname: %s\n",name);
	if(!init_l)
		init_lib();
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
	PDEBUG("getaddrinfo: %s %s\n",node ,service);
	if(!init_l)
		init_lib();
	if(proxychains_resolver)
		ret = proxy_getaddrinfo(node, service, hints, res);
	else
		ret = true_getaddrinfo(node, service, hints, res);
			
	return ret;
}
void freeaddrinfo(struct addrinfo *res)
{
	PDEBUG("freeaddrinfo %p \n",res);
	if(!init_l)
		init_lib();
	if(!proxychains_resolver)
		true_freeaddrinfo(res);
	else {
		free(res->ai_addr);
		free(res);
	}
	return;
}

int getnameinfo (const struct sockaddr * sa,
			socklen_t salen, char * host,
			socklen_t hostlen, char * serv,
			socklen_t servlen, int flags)
{
	int ret = 0;
	if(!init_l)
		init_lib();
	if(!proxychains_resolver) {
		ret = true_getnameinfo(sa,salen,host,hostlen,
				serv,servlen,flags);
	} else {
		if(hostlen) 
			strncpy(host, inet_ntoa(SOCKADDR_2(*sa)),hostlen);
		if(servlen) 
			snprintf(serv, servlen,"%d",ntohs(SOCKPORT(*sa)));
	}
	PDEBUG("getnameinfo: %s %s\n", host, serv);
	return ret;
}

struct hostent *gethostbyaddr (const void *addr, socklen_t len, int type)
{
	PDEBUG("TODO: gethostbyaddr hook\n"); 
	if(!init_l)
		init_lib();
	if(!proxychains_resolver)
		return true_gethostbyaddr(addr,len,type);
	return NULL;
}
	
