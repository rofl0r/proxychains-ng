/*
   proxychains-ng DNS daemon

   Copyright (C) 2020 rofl0r.

*/

#define _GNU_SOURCE
#include <unistd.h>
#define _POSIX_C_SOURCE 200809L
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>
#include <signal.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include "udpserver.h"
#include "sblist.h"
#include "hsearch.h"
#include "../remotedns.h"
#include "../ip_type.h"

#ifndef MAX
#define MAX(x, y) ((x) > (y) ? (x) : (y))
#endif

static struct htab *ip_lookup_table;
static sblist *hostnames;
static unsigned remote_subnet;
static const struct server* server;

#ifndef CONFIG_LOG
#define CONFIG_LOG 1
#endif
#if CONFIG_LOG
/* we log to stderr because it's not using line buffering, i.e. malloc which would need
   locking when called from different threads. for the same reason we use dprintf,
   which writes directly to an fd. */
#define dolog(...) dprintf(2, __VA_ARGS__)
#else
static void dolog(const char* fmt, ...) { }
#endif

static char* my_inet_ntoa(unsigned char *ip_buf_4_bytes, char *outbuf_16_bytes) {
	unsigned char *p;
	char *o = outbuf_16_bytes;
	unsigned char n;
	for(p = ip_buf_4_bytes; p < ip_buf_4_bytes + 4; p++) {
		n = *p;
		if(*p >= 100) {
			if(*p >= 200)
				*(o++) = '2';
			else
				*(o++) = '1';
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
	return outbuf_16_bytes;
}


/* buf needs to be long enough for an ipv6 addr, i.e. INET6_ADDRSTRLEN + 1 */
static char* ipstr(union sockaddr_union *su, char* buf) {
	int af = SOCKADDR_UNION_AF(su);
	void *ipdata = SOCKADDR_UNION_ADDRESS(su);
	inet_ntop(af, ipdata, buf, INET6_ADDRSTRLEN+1);
	char portbuf[7];
	snprintf(portbuf, sizeof portbuf, ":%u", (unsigned) ntohs(SOCKADDR_UNION_PORT(su)));
	strcat(buf, portbuf);
	return buf;
}

static int usage(char *a0) {
	dprintf(2,
		"Proxychains-NG remote dns daemon\n"
		"--------------------------------\n"
		"usage: %s -i listenip -p port -r remotesubnet\n"
		"all arguments are optional.\n"
		"by default listenip is 127.0.0.1, port 1053 and remotesubnet 224.\n\n", a0
	);
	return 1;
}

unsigned index_from_ip(ip_type4 internalip) {
	ip_type4 tmp = internalip;
	uint32_t ret;
	ret = tmp.octet[3] + (tmp.octet[2] << 8) + (tmp.octet[1] << 16);
	ret -= 1;
	return ret;
}

char *host_from_ip(ip_type4 internalip) {
	char *res = NULL;
	unsigned index = index_from_ip(internalip);
	if(index < sblist_getsize(hostnames)) {
		char **tmp = sblist_get(hostnames, index);
		if(tmp && *tmp) res = *tmp;
	}
	return res;
}

ip_type4 get_ip_from_index(unsigned index) {
	ip_type4 ret;
	index++; // so we can start at .0.0.1
	if(index > 0xFFFFFF)
		return IPT4_INVALID;
	ret.octet[0] = remote_subnet & 0xFF;
	ret.octet[1] = (index & 0xFF0000) >> 16;
	ret.octet[2] = (index & 0xFF00) >> 8;
	ret.octet[3] = index & 0xFF;
	return ret;
}

ip_type4 get_ip(char* hn) {
	htab_value *v = htab_find(ip_lookup_table, hn);
	if(v) return get_ip_from_index(v->n);
	char *n = strdup(hn);
	if(!n) return IPT4_INVALID;
	if(!sblist_add(hostnames, &n)) {
	o_out:;
		free(n);
		return IPT4_INVALID;
	}
	if(!htab_insert(ip_lookup_table, n, HTV_N(sblist_getsize(hostnames)-1))) {
		sblist_delete(hostnames, sblist_getsize(hostnames)-1);
		goto o_out;
	}
	return get_ip_from_index(sblist_getsize(hostnames)-1);
}

int main(int argc, char** argv) {
	int ch;
	const char *listenip = "127.0.0.1";
	unsigned port = 1053;
	remote_subnet = 224;
	while((ch = getopt(argc, argv, ":r:i:p:")) != -1) {
		switch(ch) {
			case 'r':
				remote_subnet = atoi(optarg);
				break;
			case 'i':
				listenip = optarg;
				break;
			case 'p':
				port = atoi(optarg);
				break;
			case ':':
				dprintf(2, "error: option -%c requires an operand\n", optopt);
				/* fall through */
			case '?':
				return usage(argv[0]);
		}
	}
	signal(SIGPIPE, SIG_IGN);
	struct server s;
	if(server_setup(&s, listenip, port)) {
		perror("server_setup");
		return 1;
	}
	server = &s;

	ip_lookup_table = htab_create(64);
	hostnames = sblist_new(sizeof(char*), 64);

	while(1) {
		struct client c;
		char ipstr_buf[INET6_ADDRSTRLEN+6+1];
		char ip4str_buf[16];
		struct at_msg msg, out;
		size_t msgl = sizeof(msg);
		int failed = 0;

#define FAIL() do { failed=1; goto sendresp; } while(0)

		if(server_waitclient(&s, &c, &msg, &msgl)) continue;
		msg.h.datalen = ntohs(msg.h.datalen);
		if(msgl != sizeof(msg.h)+msg.h.datalen) {
			dolog("%s: invalid datalen\n", ipstr(&c.addr, ipstr_buf));
			FAIL();
		}

		out.h.msgtype = msg.h.msgtype;
		if(msg.h.msgtype == ATM_GETIP) {
			if(!memchr(msg.m.host, 0, msg.h.datalen)) {
				dolog("%s: nul terminator missing\n", ipstr(&c.addr, ipstr_buf));
				FAIL();
			}
			out.h.datalen = sizeof(ip_type4);
			out.m.ip = get_ip(msg.m.host);
			failed = !memcmp(&out.m.ip, &IPT4_INVALID, 4);
			dolog("%s requested ip for %s (%s)\n", ipstr(&c.addr, ipstr_buf),
			      msg.m.host, failed?"FAIL":my_inet_ntoa((void*)&out.m.ip, ip4str_buf));
			if(failed) FAIL();
		} else if (msg.h.msgtype == ATM_GETNAME) {
			if(msg.h.datalen != 4) {
				dolog("%s: invalid len for getname request\n", ipstr(&c.addr, ipstr_buf));
				FAIL();
			}
			char *hn = host_from_ip(msg.m.ip);
			if(hn) {
				size_t l = strlen(hn);
				memcpy(out.m.host, hn, l+1);
				out.h.datalen = l+1;
			}
			dolog("%s requested name for %s (%s)\n", ipstr(&c.addr, ipstr_buf),
			      my_inet_ntoa((void*) &msg.m.ip, ip4str_buf), hn?hn:"FAIL");
			if(!hn) FAIL();
		} else {
			dolog("%s: unknown request %u\n", ipstr(&c.addr, ipstr_buf),
			      (unsigned) msg.h.msgtype);
		}
	sendresp:;
		if(failed) {
			out.h.msgtype = ATM_FAIL;
			out.h.datalen = 0;
		}
		unsigned short dlen = out.h.datalen;
		out.h.datalen = htons(dlen);
		sendto(server->fd, &out, sizeof(out.h)+dlen, 0, (void*) &c.addr, SOCKADDR_UNION_LENGTH(&c.addr));
	}
}
