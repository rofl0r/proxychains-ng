/***************************************************************************
                          core.h  -  description
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
#ifndef __CORE_HEADER
#define __CORE_HEADER
#define BUFF_SIZE 8*1024  // used to read responses from proxies.
#define     MAX_LOCALNET 1024

/*error codes*/
typedef enum
{
 SUCCESS=0,
 MEMORY_FAIL,        // malloc failed
 SOCKET_ERROR,  // look errno for more
 CHAIN_DOWN,    // no proxy in chain responds to tcp
 CHAIN_EMPTY,   //  if proxy_count = 0
 BLOCKED  //  target's port blocked on last proxy in the chain
} ERR_CODE;


typedef enum {HTTP_TYPE,SOCKS4_TYPE,SOCKS5_TYPE} proxy_type;
typedef enum {DYNAMIC_TYPE,STRICT_TYPE,RANDOM_TYPE} chain_type;
typedef enum {PLAY_STATE,DOWN_STATE,BLOCKED_STATE,BUSY_STATE} proxy_state;
typedef enum {RANDOMLY,FIFOLY} select_type;

typedef struct
{
	struct in_addr in_addr, netmask;
	unsigned short port;
} localaddr_arg;

typedef struct {
	unsigned int ip;
	unsigned short port;
	proxy_type pt;
	proxy_state ps;
	char user[256];
	char pass[256];
} proxy_data;

typedef struct {
	proxy_data *pd;
 	chain_type ct;
  	unsigned int proxy_count;
   	int sock;
    	struct sockaddr addr;
      int flags;
} thread_arg;

int connect_proxy_chain (
		int sock,
		unsigned int target_ip,
		unsigned short target_port,
		proxy_data * pd,
		unsigned int proxy_count,
		chain_type ct,
		unsigned int max_chain );

int proxychains_write_log(char *str,...);
struct hostent* proxy_gethostbyname(const char *name);


typedef int (*connect_t)(int, const struct sockaddr *, socklen_t);
connect_t true_connect;

typedef struct hostent* (*gethostbyname_t)(const char *);
gethostbyname_t true_gethostbyname;

typedef int (*getaddrinfo_t)(const char *, const char *,
		const struct addrinfo *,
		struct addrinfo **);
getaddrinfo_t true_getaddrinfo;

typedef int (*freeaddrinfo_t)(struct addrinfo *);
freeaddrinfo_t true_freeaddrinfo;

typedef int (*getnameinfo_t) (const struct sockaddr *,
		socklen_t, char *,
		socklen_t, char *,
		socklen_t, unsigned int);
getnameinfo_t true_getnameinfo;

typedef struct hostent *(*gethostbyaddr_t) (const void *, socklen_t, int);
gethostbyaddr_t true_gethostbyaddr;

int proxy_getaddrinfo(const char *node, const char *service,
		                const struct addrinfo *hints,
				                struct addrinfo **res);

struct hostent* proxy_gethostbyname(const char *name);

#ifdef DEBUG
# define PDEBUG(fmt, args...) fprintf(stderr,"DEBUG:"fmt, ## args)
#else
# define PDEBUG(fmt, args...)
#endif

#endif 
