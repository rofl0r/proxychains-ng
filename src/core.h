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
#define     MAX_LOCALNET 64
#define     MAX_DNAT 64

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
	SOCKS5_TYPE,
	RAW_TYPE
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
	sa_family_t family;
	unsigned short port;
	union {
		struct {
			struct in_addr in_addr;
			struct in_addr in_mask;
		};
		struct {
			struct in6_addr in6_addr;
			unsigned char in6_prefix;
		};
	};
} localaddr_arg;

typedef struct {
	struct in_addr orig_dst, new_dst;
	unsigned short orig_port, new_port;
} dnat_arg;

typedef struct {
	ip_type ip;
	unsigned short port;
	proxy_type pt;
	proxy_state ps;
	char user[256];
	char pass[256];
} proxy_data;



typedef enum {
	ATYP_V4 = 0x01,
	ATYP_V6 = 0x04,
	ATYP_DOM = 0x03
} ATYP;

typedef struct{
	union {
		ip_type4 v4;
		unsigned char v6[16];
		struct {
			char len;
			char name[255];
		} dom;
	} addr ;
	ATYP atyp;
} socks5_addr;

/* A structure to hold necessary information about an UDP relay server that has been set up 
with a UDP_ASSOCIATE command issued on the tcp_sockfd */
typedef struct s_udp_relay_node {
	int tcp_sockfd;	// the tcp socket on which the UDP_ASSOCIATE command has been issued. Closing this fd closes the udp relay.
	proxy_data pd; // the associated SOCKS5 server
	ip_type bnd_addr; // the BND_ADDR returned by the udp relay server in the response to the UDP_ASSOCIATE command. 
	unsigned short bnd_port; // the BND_PORT returned by the udp relay server in the response to the UDP_ASSOCIATE command.
	ip_type dst_addr; // ?? the DST_ADDR sent in the UDP_ASSOCIATE command.
	unsigned short dst_port; // ?? the DST_PORT sent in the UDP_ASSOCIATE command.
	struct s_udp_relay_node * prev;
	struct s_udp_relay_node * next;
} udp_relay_node;


/* A structure to hold the chain of udp relay servers assiociated with a client socket */
typedef struct s_udp_relay_chain {
	int sockfd; // the client socket for which the chain of relays has been set up
	udp_relay_node * head; // head of the linked list of udp_relay_node
	struct sockaddr* connected_peer_addr; // used to store the address of the peer which the sockfd is connected to (in case connect() is used on the socket)
	socklen_t connected_peer_addr_len;
	struct s_udp_relay_chain * prev;
	struct s_udp_relay_chain * next;
} udp_relay_chain;

typedef struct {
	udp_relay_chain * head;
	udp_relay_chain * tail;
} udp_relay_chain_list;

int connect_proxy_chain (int sock, ip_type target_ip, unsigned short target_port,
			 proxy_data * pd, unsigned int proxy_count, chain_type ct,
			 unsigned int max_chain );

void proxychains_write_log(char *str, ...);

typedef int (*close_t)(int);
typedef int (*close_range_t)(unsigned, unsigned, int);
typedef int (*connect_t)(int, const struct sockaddr *, socklen_t);
typedef struct hostent* (*gethostbyname_t)(const char *);
typedef int (*freeaddrinfo_t)(struct addrinfo *);
typedef struct hostent *(*gethostbyaddr_t) (const void *, socklen_t, int);

typedef int (*getaddrinfo_t)(const char *, const char *, const struct addrinfo *, 
			     struct addrinfo **);

typedef int (*getnameinfo_t) (const struct sockaddr *, socklen_t, char *, 
			      GN_NODELEN_T, char *, GN_SERVLEN_T, GN_FLAGS_T);

typedef ssize_t (*sendto_t) (int sockfd, const void *buf, size_t len, int flags,
			     const struct sockaddr *dest_addr, socklen_t addrlen);

typedef ssize_t (*send_t) (int sockfd, const void *buf, size_t len, int flags);

typedef ssize_t (*recv_t) (int sockfd, void *buf, size_t len, int flags);

typedef ssize_t (*recvfrom_t) (int sockfd, void *buf, size_t len, int flags, 
			struct sockaddr *src_addr, socklen_t *addrlen);

typedef ssize_t (*sendmsg_t) (int sockfd, const struct msghdr *msg, int flags);
typedef int (*sendmmsg_t) (int sockfd, struct mmsghdr* msgvec, unsigned int vlen, int flags);
typedef ssize_t (*recvmsg_t) (int sockfd, struct msghdr *msg, int flags);
typedef int (*getpeername_t) (int sockfd, struct sockaddr *restrict addr, socklen_t *restrict addrlen);


extern connect_t true_connect;
extern gethostbyname_t true_gethostbyname;
extern getaddrinfo_t true_getaddrinfo;
extern freeaddrinfo_t true_freeaddrinfo;
extern getnameinfo_t true_getnameinfo;
extern gethostbyaddr_t true_gethostbyaddr;
extern sendto_t true_sendto;
extern recvfrom_t true_recvfrom;
extern recv_t true_recv;
extern send_t true_send;
extern sendmsg_t true_sendmsg;
extern sendmmsg_t true_sendmmsg;
extern recvmsg_t true_recvmsg;
extern getpeername_t true_getpeername;

struct gethostbyname_data {
	struct hostent hostent_space;
	in_addr_t resolved_addr;
	char *resolved_addr_p[2];
	char addr_name[256];
};

struct hostent* proxy_gethostbyname(const char *name, struct gethostbyname_data *data);
struct hostent* proxy_gethostbyname_old(const char *name);

int proxy_getaddrinfo(const char *node, const char *service, 
		      const struct addrinfo *hints, struct addrinfo **res);
void proxy_freeaddrinfo(struct addrinfo *res);

void core_initialize(void);
void core_unload(void);

static int udp_associate(int sock, ip_type * dst_addr, unsigned short dst_port, ip_type *bnd_addr, unsigned short *bnd_port, char *user, char *pass);
udp_relay_chain* get_relay_chain(udp_relay_chain_list chains_list, int sockfd);
void del_relay_chain(udp_relay_chain_list* chains_list, udp_relay_chain* chain);
void add_relay_chain(udp_relay_chain_list* chains_list, udp_relay_chain* new_chain);
int free_relay_chain(udp_relay_chain chain);
udp_relay_chain * open_relay_chain(proxy_data *pd, unsigned int proxy_count, chain_type ct, unsigned int max_chains);
int send_udp_packet(int sockfd, udp_relay_chain chain, ip_type target_ip, unsigned short target_port, char frag, char * data, unsigned int data_len, int flags);
int receive_udp_packet(int sockfd, udp_relay_chain chain, ip_type* src_addr, unsigned short* src_port, char* data, unsigned int data_len  );
size_t get_msg_iov_total_len(struct iovec* iov, size_t iov_len);
size_t write_buf_to_iov(void* buff, size_t buff_len, struct iovec* iov, size_t iov_len);
size_t write_iov_to_buf(void* buff, size_t buff_len, struct iovec* iov, size_t iov_len);
int is_from_chain_head(udp_relay_chain chain, struct sockaddr* src_addr);
int unsocksify_udp_packet(void* in_buffer, size_t in_buffer_len, udp_relay_chain chain, ip_type* src_ip, unsigned short* src_port, void* udp_data, size_t* udp_data_len);
int socksify_udp_packet(void* udp_data, size_t udp_data_len, udp_relay_chain chain, ip_type dst_ip, unsigned short dst_port, void* buffer, size_t* buffer_len);
int encapsulate_udp_packet(udp_relay_chain chain, socks5_addr dst_addr, unsigned short dst_port, void* buffer, size_t* buffer_len);
void set_connected_peer_addr(udp_relay_chain* chain, struct sockaddr* addr, socklen_t addrlen);

#include "debug.h"

#endif

//RcB: DEP "core.c"
//RcB: DEP "libproxychains.c"
//RcB: LINK "-Wl,--no-as-needed -ldl -lpthread"

