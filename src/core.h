/***************************************************************************
                          core.h  -  description
                             -------------------
    begin                : Tue May 14 2002
    copyright          :  netcreature (C) 2002
    email                 : netcreature@users.sourceforge.net
 ***************************************************************************
 ***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 ***************************************************************************/

#include <unistd.h>
#include <stdint.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#ifndef __CORE_HEADER
#define __CORE_HEADER
#define BUFF_SIZE 8*1024  // used to read responses from proxies.
#define     MAX_LOCALNET 64
#define     MAX_CHAIN_LISTS 64
#define     MAX_CHAIN 512

#include "ip_type.h"

/*error codes*/
typedef enum {
	SUCCESS=0,
	MEMORY_FAIL,        // malloc failed
	SOCKET_ERROR,  // look errno for more
	CHAIN_DOWN,    // no proxy in chain responds to tcp
	CHAIN_EMPTY,   //  if proxy_count = 0
	BLOCKED  //  target's port blocked on last proxy in the chain
} ERR_CODE;

typedef enum {
	HTTP_TYPE,
	SOCKS4_TYPE,
	SOCKS5_TYPE
} proxy_type;

typedef enum {
	DYNAMIC_TYPE,
	STRICT_TYPE,
	RANDOM_TYPE,
	ROUND_ROBIN_TYPE
} chain_type;

typedef enum {
	PLAY_STATE,
	DOWN_STATE,
	BLOCKED_STATE,
	BUSY_STATE
} proxy_state;

typedef enum {
	RANDOMLY,
	FIFOLY
} select_type;

typedef struct {
	struct in_addr in_addr, netmask;
	unsigned short port;
} localaddr_arg;

typedef struct {
	ip_type ip;
	unsigned short port;
	proxy_type pt;
	proxy_state ps;
	char user[256];
	char pass[256];
} proxy_data;

typedef struct {
	char *name;
	chain_type ct;
	proxy_data *pd;
	unsigned int count;
	unsigned int offset;
	unsigned int max_chain;
	int tcp_read_time_out;
	int tcp_connect_time_out;
} proxy_chain;

typedef struct {
	chain_type ct;
	proxy_chain *pc[MAX_CHAIN_LISTS];
	unsigned int count;
	localaddr_arg localnet_addr[MAX_LOCALNET];
	size_t num_localnet_addr;
	int remote_dns_subnet; // -1 means no remote dns
	int tcp_read_time_out;
	int tcp_connect_time_out;
	proxy_chain *selected;
} proxy_chain_list;

int connect_proxy_chain (int sock, ip_type target_ip, unsigned short target_port,
			 proxy_chain *pc );

void proxychains_write_log(char *str, ...);

typedef int (*close_t)(int);
typedef int (*connect_t)(int, const struct sockaddr *, socklen_t);
typedef struct hostent* (*gethostbyname_t)(const char *);
typedef int (*freeaddrinfo_t)(struct addrinfo *);
typedef struct hostent *(*gethostbyaddr_t) (const void *, socklen_t, int);

typedef int (*getaddrinfo_t)(const char *, const char *, const struct addrinfo *, 
			     struct addrinfo **);

typedef int (*getnameinfo_t) (const struct sockaddr *, socklen_t, char *, 
			      socklen_t, char *, socklen_t, int);


extern connect_t true_connect;
extern gethostbyname_t true_gethostbyname;
extern getaddrinfo_t true_getaddrinfo;
extern freeaddrinfo_t true_freeaddrinfo;
extern getnameinfo_t true_getnameinfo;
extern gethostbyaddr_t true_gethostbyaddr;

struct gethostbyname_data {
	struct hostent hostent_space;
	in_addr_t resolved_addr;
	char *resolved_addr_p[2];
	char addr_name[1024 * 8];
};

struct hostent* proxy_gethostbyname(const char *name, struct gethostbyname_data *data);

int proxy_getaddrinfo(const char *node, const char *service, 
		      const struct addrinfo *hints, struct addrinfo **res);
void proxy_freeaddrinfo(struct addrinfo *res);

void core_initialize(void);
void core_unload(void);

#include "debug.h"

#endif

//RcB: DEP "core.c"
//RcB: DEP "libproxychains.c"
//RcB: LINK "-Wl,--no-as-needed -ldl -lpthread"

