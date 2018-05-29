/***************************************************************************
                          core.c  -  description
                             -------------------
    begin                : Tue May 14 2002
    copyright            :  netcreature (C) 2002
    email                : netcreature@users.sourceforge.net
 ***************************************************************************
 *     GPL *
 ***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 ***************************************************************************/

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>

#include <sys/utsname.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <poll.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <time.h>
#include <sys/time.h>
#include <stdarg.h>
#include <assert.h>

#include "core.h"
#include "common.h"
#include "allocator_thread.h"

extern int tcp_read_time_out;
extern int tcp_connect_time_out;
extern int proxychains_quiet_mode;
extern unsigned int proxychains_proxy_offset;
extern unsigned int remote_dns_subnet;

static int poll_retry(struct pollfd *fds, nfds_t nfsd, int timeout) {
	int ret;
	int time_remain = timeout;
	int time_elapsed = 0;

	struct timeval start_time;
	struct timeval tv;

	gettimeofday(&start_time, NULL);

	do {
		//printf("Retry %d\n", time_remain);
		ret = poll(fds, nfsd, time_remain);
		gettimeofday(&tv, NULL);
		time_elapsed = ((tv.tv_sec - start_time.tv_sec) * 1000 + (tv.tv_usec - start_time.tv_usec) / 1000);
		//printf("Time elapsed %d\n", time_elapsed);
		time_remain = timeout - time_elapsed;
	} while(ret == -1 && errno == EINTR && time_remain > 0);

	//if (ret == -1)
	//printf("Return %d %d %s\n", ret, errno, strerror(errno));
	return ret;
}

static void encode_base_64(char *src, char *dest, int max_len) {
	static const char base64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	int n, l, i;
	l = strlen(src);
	max_len = (max_len - 1) / 4;
	for(i = 0; i < max_len; i++, src += 3, l -= 3) {
		switch (l) {
			case 0:
				break;
			case 1:
				n = src[0] << 16;
				*dest++ = base64[(n >> 18) & 077];
				*dest++ = base64[(n >> 12) & 077];
				*dest++ = '=';
				*dest++ = '=';
				break;
			case 2:
				n = src[0] << 16 | src[1] << 8;
				*dest++ = base64[(n >> 18) & 077];
				*dest++ = base64[(n >> 12) & 077];
				*dest++ = base64[(n >> 6) & 077];
				*dest++ = '=';
				break;
			default:
				n = src[0] << 16 | src[1] << 8 | src[2];
				*dest++ = base64[(n >> 18) & 077];
				*dest++ = base64[(n >> 12) & 077];
				*dest++ = base64[(n >> 6) & 077];
				*dest++ = base64[n & 077];
		}
		if(l < 3)
			break;
	}
	*dest++ = 0;
}

void proxychains_write_log(char *str, ...) {
	char buff[1024*20];
	va_list arglist;
	if(!proxychains_quiet_mode) {
		va_start(arglist, str);
		vsnprintf(buff, sizeof(buff), str, arglist);
		va_end(arglist);
		fprintf(stderr, "%s", buff);
		fflush(stderr);
	}
}

static int write_n_bytes(int fd, char *buff, size_t size) {
	int i = 0;
	size_t wrote = 0;
	for(;;) {
		i = write(fd, &buff[wrote], size - wrote);
		if(i <= 0)
			return i;
		wrote += i;
		if(wrote == size)
			return wrote;
	}
}

static int read_n_bytes(int fd, char *buff, size_t size) {
	int ready;
	size_t i;
	struct pollfd pfd[1];

	pfd[0].fd = fd;
	pfd[0].events = POLLIN;
	for(i = 0; i < size; i++) {
		pfd[0].revents = 0;
		ready = poll_retry(pfd, 1, tcp_read_time_out);
		if(ready != 1 || !(pfd[0].revents & POLLIN) || 1 != read(fd, &buff[i], 1))
			return -1;
	}
	return (int) size;
}

static int timed_connect(int sock, const struct sockaddr *addr, socklen_t len) {
	int ret, value;
	socklen_t value_len;
	struct pollfd pfd[1];
	PFUNC();

	pfd[0].fd = sock;
	pfd[0].events = POLLOUT;
	fcntl(sock, F_SETFL, O_NONBLOCK);
	ret = true_connect(sock, addr, len);
	PDEBUG("\nconnect ret=%d\n", ret);
	
	if(ret == -1 && errno == EINPROGRESS) {
		ret = poll_retry(pfd, 1, tcp_connect_time_out);
		PDEBUG("\npoll ret=%d\n", ret);
		if(ret == 1) {
			value_len = sizeof(socklen_t);
			getsockopt(sock, SOL_SOCKET, SO_ERROR, &value, &value_len);
			PDEBUG("\nvalue=%d\n", value);
			if(!value)
				ret = 0;
			else
				ret = -1;
		} else {
			ret = -1;
		}
	} else {
#ifdef DEBUG
		if(ret == -1)
			perror("true_connect");
#endif
		if(ret != 0)
			ret = -1;
	}

	fcntl(sock, F_SETFL, !O_NONBLOCK);
	return ret;
}


#define INVALID_INDEX 0xFFFFFFFFU
static int tunnel_to(int sock, ip_type ip, unsigned short port, proxy_type pt, char *user, char *pass) {
	char *dns_name = NULL;
	char hostnamebuf[MSG_LEN_MAX];
	size_t dns_len = 0;

	PFUNC();

	// we use ip addresses with 224.* to lookup their dns name in our table, to allow remote DNS resolution
	// the range 224-255.* is reserved, and it won't go outside (unless the app does some other stuff with
	// the results returned from gethostbyname et al.)
	// the hardcoded number 224 can now be changed using the config option remote_dns_subnet to i.e. 127
	if(!ip.is_v6 && ip.addr.v4.octet[0] == remote_dns_subnet) {
		dns_len = at_get_host_for_ip(ip.addr.v4, hostnamebuf);
		if(!dns_len) goto err;
		else dns_name = hostnamebuf;
	}
	
	PDEBUG("host dns %s\n", dns_name ? dns_name : "<NULL>");

	size_t ulen = strlen(user);
	size_t passlen = strlen(pass);

	if(ulen > 0xFF || passlen > 0xFF || dns_len > 0xFF) {
		proxychains_write_log(LOG_PREFIX "error: maximum size of 255 for user/pass or domain name!\n");
		goto err;
	}

	int len;
	unsigned char buff[BUFF_SIZE];
	char ip_buf[INET6_ADDRSTRLEN];
	int v6 = ip.is_v6;
	
	switch (pt) {
		case HTTP_TYPE:{
			if(!dns_len) {
				if(!inet_ntop(v6?AF_INET6:AF_INET,ip.addr.v6,ip_buf,sizeof ip_buf)) {
					proxychains_write_log(LOG_PREFIX "error: ip address conversion failed\n");
					goto err;
				}
				dns_name = ip_buf;
			}
			#define HTTP_AUTH_MAX ((0xFF * 2) + 1 + 1) /* 2 * 0xff: username and pass, plus 1 for ':' and 1 for zero terminator. */
			char src[HTTP_AUTH_MAX];
			char dst[(4 * HTTP_AUTH_MAX)];
			if(ulen) {
				snprintf(src, sizeof(src), "%s:%s", user, pass);
				encode_base_64(src, dst, sizeof(dst));
			} else dst[0] = 0;

			uint16_t hs_port = ntohs(port);
			len = snprintf((char *) buff, sizeof(buff),
			               "CONNECT %s:%d HTTP/1.0\r\nHost: %s:%d\r\n%s%s%s\r\n",
			                dns_name, hs_port,
			                dns_name, hs_port,
			                ulen ? "Proxy-Authorization: Basic " : dst,
			                dst, ulen ? "\r\n" : dst);

			if(len < 0 || len != send(sock, buff, len, 0))
				goto err;

			len = 0;
			// read header byte by byte.
			while(len < BUFF_SIZE) {
				if(1 == read_n_bytes(sock, (char *) (buff + len), 1))
					len++;
				else
					goto err;
				if(len > 4 &&
				   buff[len - 1] == '\n' &&
				   buff[len - 2] == '\r' && buff[len - 3] == '\n' && buff[len - 4] == '\r')
					break;
			}

			// if not ok (200) or response greather than BUFF_SIZE return BLOCKED;
			if(len == BUFF_SIZE || !(buff[9] == '2' && buff[10] == '0' && buff[11] == '0')) {
				PDEBUG("HTTP proxy blocked: buff=\"%s\"\n", buff);
				return BLOCKED;
			}

			return SUCCESS;
		}
		break;
		case SOCKS4_TYPE:{
			if(v6) {
				proxychains_write_log(LOG_PREFIX "error: SOCKS4 doesn't support ipv6 addresses\n");
				goto err;
			}
			buff[0] = 4;	// socks version
			buff[1] = 1;	// connect command
			memcpy(&buff[2], &port, 2);	// dest port
			if(dns_len) {
				ip.addr.v4.octet[0] = 0;
				ip.addr.v4.octet[1] = 0;
				ip.addr.v4.octet[2] = 0;
				ip.addr.v4.octet[3] = 1;
			}
			memcpy(&buff[4], &ip.addr.v4, 4);	// dest host
			len = ulen + 1;	// username
			if(len > 1)
				memcpy(&buff[8], user, len);
			else {
				buff[8] = 0;
			}

			// do socksv4a dns resolution on the server
			if(dns_len) {
				memcpy(&buff[8 + len], dns_name, dns_len + 1);
				len += dns_len + 1;
			}

			if((len + 8) != write_n_bytes(sock, (char *) buff, (8 + len)))
				goto err;

			if(8 != read_n_bytes(sock, (char *) buff, 8))
				goto err;

			if(buff[0] != 0 || buff[1] != 90)
				return BLOCKED;

			return SUCCESS;
		}
		break;
		case SOCKS5_TYPE:{
			int n_methods = ulen ? 2 : 1;
			buff[0] = 5;	// version
			buff[1] = n_methods ;	// number of methods
			buff[2] = 0;	// no auth method
			if(ulen) buff[3] = 2;    /// auth method -> username / password
			if(2+n_methods != write_n_bytes(sock, (char *) buff, 2+n_methods))
				goto err;

			if(2 != read_n_bytes(sock, (char *) buff, 2))
				goto err;

			if(buff[0] != 5 || (buff[1] != 0 && buff[1] != 2)) {
				if(buff[0] == 5 && buff[1] == 0xFF)
					return BLOCKED;
				else
					goto err;
			}

			if(buff[1] == 2) {
				// authentication
				char in[2];
				char out[515];
				char *cur = out;
				size_t c;
				*cur++ = 1;	// version
				c = ulen & 0xFF;
				*cur++ = c;
				memcpy(cur, user, c);
				cur += c;
				c = passlen & 0xFF;
				*cur++ = c;
				memcpy(cur, pass, c);
				cur += c;

				if((cur - out) != write_n_bytes(sock, out, cur - out))
					goto err;


				if(2 != read_n_bytes(sock, in, 2))
					goto err;
	/* according to RFC 1929 the version field for the user/pass auth sub-
	   negotiation should be 1, which is kinda counter-intuitive, so there
	   are some socks5 proxies that return 5 instead. other programs like
	   curl work fine when the version is 5, so let's do the same and accept
	   either of them. */
				if(!(in[0] == 5 || in[0] == 1))
					goto err;
				if(in[1] != 0)
					return BLOCKED;
			}
			int buff_iter = 0;
			buff[buff_iter++] = 5;	// version
			buff[buff_iter++] = 1;	// connect
			buff[buff_iter++] = 0;	// reserved

			if(!dns_len) {
				buff[buff_iter++] = v6 ? 4 : 1;	// ip v4/v6
				memcpy(buff + buff_iter, ip.addr.v6, v6?16:4);	// dest host
				buff_iter += v6?16:4;
			} else {
				buff[buff_iter++] = 3;	//dns
				buff[buff_iter++] = dns_len & 0xFF;
				memcpy(buff + buff_iter, dns_name, dns_len);
				buff_iter += dns_len;
			}

			memcpy(buff + buff_iter, &port, 2);	// dest port
			buff_iter += 2;


			if(buff_iter != write_n_bytes(sock, (char *) buff, buff_iter))
				goto err;

			if(4 != read_n_bytes(sock, (char *) buff, 4))
				goto err;

			if(buff[0] != 5 || buff[1] != 0)
				goto err;

			switch (buff[3]) {
				case 1:
					len = 4;
					break;
				case 4:
					len = 16;
					break;
				case 3:
					len = 0;
					if(1 != read_n_bytes(sock, (char *) &len, 1))
						goto err;
					break;
				default:
					goto err;
			}

			if(len + 2 != read_n_bytes(sock, (char *) buff, len + 2))
				goto err;

			return SUCCESS;
		}
		break;
	}

	err:
	return SOCKET_ERROR;
}

#define TP " ... "
#define DT "Dynamic chain"
#define ST "Strict chain"
#define RT "Random chain"
#define RRT "Round Robin chain"

static int start_chain(int *fd, proxy_data * pd, char *begin_mark) {
	int v6 = pd->ip.is_v6;

	*fd = socket(v6?PF_INET6:PF_INET, SOCK_STREAM, 0);
	if(*fd == -1)
		goto error;
	
	char ip_buf[INET6_ADDRSTRLEN];
	if(!inet_ntop(v6?AF_INET6:AF_INET,pd->ip.addr.v6,ip_buf,sizeof ip_buf))
		goto error;

	proxychains_write_log(LOG_PREFIX "%s " TP " %s:%d ",
			      begin_mark, ip_buf, htons(pd->port));
	pd->ps = PLAY_STATE;
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = pd->port,
		.sin_addr.s_addr = (in_addr_t) pd->ip.addr.v4.as_int
	};
	struct sockaddr_in6 addr6 = {
		.sin6_family = AF_INET6,
		.sin6_port = pd->port,
	};
	if(v6) memcpy(&addr6.sin6_addr.s6_addr, pd->ip.addr.v6, 16);
	if(timed_connect(*fd, (struct sockaddr *) (v6?(void*)&addr6:(void*)&addr), v6?sizeof(addr6):sizeof(addr))) {
		pd->ps = DOWN_STATE;
		goto error1;
	}
	pd->ps = BUSY_STATE;
	return SUCCESS;
	error1:
	proxychains_write_log(TP " timeout\n");
	error:
	if(*fd != -1)
		close(*fd);
	return SOCKET_ERROR;
}

static proxy_data *select_proxy(select_type how, proxy_data * pd, unsigned int proxy_count, unsigned int *offset) {
	unsigned int i = 0, k = 0;
	if(*offset >= proxy_count)
		return NULL;
	switch (how) {
		case RANDOMLY:
			do {
				k++;
				i = rand() % proxy_count;
			} while(pd[i].ps != PLAY_STATE && k < proxy_count * 100);
			break;
		case FIFOLY:
			for(i = *offset; i < proxy_count; i++) {
				if(pd[i].ps == PLAY_STATE) {
					*offset = i;
					break;
				}
			}
		default:
			break;
	}
	if(i >= proxy_count)
		i = 0;
	return (pd[i].ps == PLAY_STATE) ? &pd[i] : NULL;
}


static void release_all(proxy_data * pd, unsigned int proxy_count) {
	unsigned int i;
	for(i = 0; i < proxy_count; i++)
		pd[i].ps = PLAY_STATE;
	return;
}

static void release_busy(proxy_data * pd, unsigned int proxy_count) {
	unsigned int i;
	for(i = 0; i < proxy_count; i++)
		if(pd[i].ps == BUSY_STATE)
			pd[i].ps = PLAY_STATE;
	return;
}

static unsigned int calc_alive(proxy_data * pd, unsigned int proxy_count) {
	unsigned int i;
	int alive_count = 0;
	release_busy(pd, proxy_count);
	for(i = 0; i < proxy_count; i++)
		if(pd[i].ps == PLAY_STATE)
			alive_count++;
	return alive_count;
}


static int chain_step(int ns, proxy_data * pfrom, proxy_data * pto) {
	int retcode = -1;
	char *hostname;
	char hostname_buf[MSG_LEN_MAX];
	char ip_buf[INET6_ADDRSTRLEN];
	int v6 = pto->ip.is_v6;

	PFUNC();

	if(!v6 && pto->ip.addr.v4.octet[0] == remote_dns_subnet) {
		if(!at_get_host_for_ip(pto->ip.addr.v4, hostname_buf)) goto usenumericip;
		else hostname = hostname_buf;
	} else {
	usenumericip:
		if(!inet_ntop(v6?AF_INET6:AF_INET,pto->ip.addr.v6,ip_buf,sizeof ip_buf)) {
			pto->ps = DOWN_STATE;
			proxychains_write_log("<--ip conversion error!\n");
			close(ns);
			return SOCKET_ERROR;
		}
		hostname = ip_buf;
	}

	proxychains_write_log(TP " %s:%d ", hostname, htons(pto->port));
	retcode = tunnel_to(ns, pto->ip, pto->port, pfrom->pt, pfrom->user, pfrom->pass);
	switch (retcode) {
		case SUCCESS:
			pto->ps = BUSY_STATE;
			break;
		case BLOCKED:
			pto->ps = BLOCKED_STATE;
			proxychains_write_log("<--denied\n");
			close(ns);
			break;
		case SOCKET_ERROR:
			pto->ps = DOWN_STATE;
			proxychains_write_log("<--socket error or timeout!\n");
			close(ns);
			break;
	}
	return retcode;
}

int connect_proxy_chain(int sock, ip_type target_ip,
			unsigned short target_port, proxy_data * pd,
			unsigned int proxy_count, chain_type ct, unsigned int max_chain) {
	proxy_data p4;
	proxy_data *p1, *p2, *p3;
	int ns = -1;
	int rc = -1;
	unsigned int offset = 0;
	unsigned int alive_count = 0;
	unsigned int curr_len = 0;
	unsigned int curr_pos = 0;
	unsigned int looped = 0; // went back to start of list in RR mode

	p3 = &p4;

	PFUNC();

	again:
	rc = -1;
	DUMP_PROXY_CHAIN(pd, proxy_count);

	switch (ct) {
		case DYNAMIC_TYPE:
			alive_count = calc_alive(pd, proxy_count);
			offset = 0;
			do {
				if(!(p1 = select_proxy(FIFOLY, pd, proxy_count, &offset)))
					goto error_more;
			} while(SUCCESS != start_chain(&ns, p1, DT) && offset < proxy_count);
			for(;;) {
				p2 = select_proxy(FIFOLY, pd, proxy_count, &offset);
				if(!p2)
					break;
				if(SUCCESS != chain_step(ns, p1, p2)) {
					PDEBUG("GOTO AGAIN 1\n");
					goto again;
				}
				p1 = p2;
			}
			//proxychains_write_log(TP);
			p3->ip = target_ip;
			p3->port = target_port;
			if(SUCCESS != chain_step(ns, p1, p3))
				goto error;
			break;

		case ROUND_ROBIN_TYPE:
			alive_count = calc_alive(pd, proxy_count);
			curr_pos = offset = proxychains_proxy_offset;
			if(alive_count < max_chain)
				goto error_more;
                        PDEBUG("1:rr_offset = %d, curr_pos = %d\n", offset, curr_pos);
			/* Check from current RR offset til end */
			for (;rc != SUCCESS;) {
				if (!(p1 = select_proxy(FIFOLY, pd, proxy_count, &offset))) {
					/* We've reached the end of the list, go to the start */
 					offset = 0;
					looped++;
					continue;
				} else if (looped && rc > 0 && offset >= curr_pos) {
 					PDEBUG("GOTO MORE PROXIES 0\n");
					/* We've gone back to the start and now past our starting position */
					proxychains_proxy_offset = 0;
 					goto error_more;
 				}
 				PDEBUG("2:rr_offset = %d\n", offset);
 				rc=start_chain(&ns, p1, RRT);
			}
			/* Create rest of chain using RR */
			for(curr_len = 1; curr_len < max_chain;) {
				PDEBUG("3:rr_offset = %d, curr_len = %d, max_chain = %d\n", offset, curr_len, max_chain);
				p2 = select_proxy(FIFOLY, pd, proxy_count, &offset);
				if(!p2) {
					/* Try from the beginning to where we started */
					offset = 0;
					continue;
				} else if(SUCCESS != chain_step(ns, p1, p2)) {
					PDEBUG("GOTO AGAIN 1\n");
					goto again;
				} else
					p1 = p2;
				curr_len++;
			}
			//proxychains_write_log(TP);
			p3->ip = target_ip;
			p3->port = target_port;
			proxychains_proxy_offset = offset+1;
			PDEBUG("pd_offset = %d, curr_len = %d\n", proxychains_proxy_offset, curr_len);
			if(SUCCESS != chain_step(ns, p1, p3))
				goto error;
			break;

		case STRICT_TYPE:
			alive_count = calc_alive(pd, proxy_count);
			offset = 0;
			if(!(p1 = select_proxy(FIFOLY, pd, proxy_count, &offset))) {
				PDEBUG("select_proxy failed\n");
				goto error_strict;
			}
			if(SUCCESS != start_chain(&ns, p1, ST)) {
				PDEBUG("start_chain failed\n");
				goto error_strict;
			}
			while(offset < proxy_count) {
				if(!(p2 = select_proxy(FIFOLY, pd, proxy_count, &offset)))
					break;
				if(SUCCESS != chain_step(ns, p1, p2)) {
					PDEBUG("chain_step failed\n");
					goto error_strict;
				}
				p1 = p2;
			}
			//proxychains_write_log(TP);
			p3->ip = target_ip;
			p3->port = target_port;
			if(SUCCESS != chain_step(ns, p1, p3))
				goto error;
			break;

		case RANDOM_TYPE:
			alive_count = calc_alive(pd, proxy_count);
			if(alive_count < max_chain)
				goto error_more;
			curr_len = offset = 0;
			do {
				if(!(p1 = select_proxy(RANDOMLY, pd, proxy_count, &offset)))
					goto error_more;
			} while(SUCCESS != start_chain(&ns, p1, RT) && offset < max_chain);
			while(++curr_len < max_chain) {
				if(!(p2 = select_proxy(RANDOMLY, pd, proxy_count, &offset)))
					goto error_more;
				if(SUCCESS != chain_step(ns, p1, p2)) {
					PDEBUG("GOTO AGAIN 2\n");
					goto again;
				}
				p1 = p2;
			}
			//proxychains_write_log(TP);
			p3->ip = target_ip;
			p3->port = target_port;
			if(SUCCESS != chain_step(ns, p1, p3))
				goto error;

	}

	proxychains_write_log(TP " OK\n");
	dup2(ns, sock);
	close(ns);
	return 0;
	error:
	if(ns != -1)
		close(ns);
	errno = ECONNREFUSED;	// for nmap ;)
	return -1;

	error_more:
	proxychains_write_log("\n!!!need more proxies!!!\n");
	error_strict:
	PDEBUG("error\n");
	
	release_all(pd, proxy_count);
	if(ns != -1)
		close(ns);
	errno = ETIMEDOUT;
	return -1;
}

void core_initialize(void) {
}

void core_unload(void) {
}

static void gethostbyname_data_setstring(struct gethostbyname_data* data, char* name) {
	snprintf(data->addr_name, sizeof(data->addr_name), "%s", name);
	data->hostent_space.h_name = data->addr_name;
}

extern ip_type4 hostsreader_get_numeric_ip_for_name(const char* name);
struct hostent *proxy_gethostbyname(const char *name, struct gethostbyname_data* data) {
	PFUNC();
	char buff[256];

	data->resolved_addr_p[0] = (char *) &data->resolved_addr;
	data->resolved_addr_p[1] = NULL;

	data->hostent_space.h_addr_list = data->resolved_addr_p;
	// let aliases point to the NULL member, mimicking an empty list.
	data->hostent_space.h_aliases = &data->resolved_addr_p[1];

	data->resolved_addr = 0;
	data->hostent_space.h_addrtype = AF_INET;
	data->hostent_space.h_length = sizeof(in_addr_t);

	gethostname(buff, sizeof(buff));

	if(!strcmp(buff, name)) {
		data->resolved_addr = inet_addr(buff);
		if(data->resolved_addr == (in_addr_t) (-1))
			data->resolved_addr = (in_addr_t) (ip_type_localhost.addr.v4.as_int);
		goto retname;
	}

	// this iterates over the "known hosts" db, usually /etc/hosts
	ip_type4 hdb_res = hostsreader_get_numeric_ip_for_name(name);
	if(hdb_res.as_int != ip_type_invalid.addr.v4.as_int) {
		data->resolved_addr = hdb_res.as_int;
		goto retname;
	}
	
	data->resolved_addr = at_get_ip_for_host((char*) name, strlen(name)).as_int;
	if(data->resolved_addr == (in_addr_t) ip_type_invalid.addr.v4.as_int) return NULL;

	retname:

	gethostbyname_data_setstring(data, (char*) name);
	
	PDEBUG("return hostent space\n");
	
	return &data->hostent_space;
}

struct addrinfo_data {
	struct addrinfo addrinfo_space;
	struct sockaddr sockaddr_space;
	char addr_name[256];
};

void proxy_freeaddrinfo(struct addrinfo *res) {
	PFUNC();
	free(res);
}

#if defined(IS_MAC) || defined(IS_OPENBSD) || defined(IS_SOLARIS)
#if defined(IS_OPENBSD) || defined(IS_SOLARIS) /* OpenBSD and Solaris has its own incompatible getservbyname_r */
#define getservbyname_r mygetservbyname_r
#endif
/* getservbyname on mac is using thread local storage, so we dont need mutex 
   TODO: check if the same applies to OpenBSD */
static int getservbyname_r(const char* name, const char* proto, struct servent* result_buf, 
			   char* buf, size_t buflen, struct servent** result) {
	PFUNC();
	struct servent *res;
	int ret;
	(void) buf; (void) buflen;
	res = getservbyname(name, proto);
	if(res) {
		*result_buf = *res;
		*result = result_buf;
		ret = 0;
	} else {
		*result = NULL;
		ret = ENOENT;
	}
	return ret;
}
#endif

int proxy_getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res) {
	struct gethostbyname_data ghdata;
	struct addrinfo_data *space;
	struct servent *se = NULL;
	struct hostent *hp = NULL;
	struct servent se_buf;
	struct addrinfo *p;
	char buf[1024];
	int port;
	PFUNC();

//      printf("proxy_getaddrinfo node %s service %s\n",node,service);
	space = calloc(1, sizeof(struct addrinfo_data));
	if(!space) goto err1;

	if(node && !inet_aton(node, &((struct sockaddr_in *) &space->sockaddr_space)->sin_addr)) {
		/* some folks (nmap) use getaddrinfo() with AI_NUMERICHOST to check whether a string
		   containing a numeric ip was passed. we must return failure in that case. */
		if(hints && (hints->ai_flags & AI_NUMERICHOST)) {
			free(space);
			return EAI_NONAME;
		}
		hp = proxy_gethostbyname(node, &ghdata);
		if(hp)
			memcpy(&((struct sockaddr_in *) &space->sockaddr_space)->sin_addr,
			       *(hp->h_addr_list), sizeof(in_addr_t));
		else
			goto err2;
	}
	if(service) getservbyname_r(service, NULL, &se_buf, buf, sizeof(buf), &se);

	port = se ? se->s_port : htons(atoi(service ? service : "0"));
	((struct sockaddr_in *) &space->sockaddr_space)->sin_port = port;

	*res = p = &space->addrinfo_space;
	assert((size_t)p == (size_t) space);

	p->ai_addr = &space->sockaddr_space;
	if(node)
		snprintf(space->addr_name, sizeof(space->addr_name), "%s", node);
	p->ai_canonname = space->addr_name;
	p->ai_next = NULL;
	p->ai_family = space->sockaddr_space.sa_family = AF_INET;
	p->ai_addrlen = sizeof(space->sockaddr_space);

	if(hints) {
		p->ai_socktype = hints->ai_socktype;
		p->ai_flags = hints->ai_flags;
		p->ai_protocol = hints->ai_protocol;
	} else {
#ifndef AI_V4MAPPED
#define AI_V4MAPPED 0
#endif
		p->ai_flags = (AI_V4MAPPED | AI_ADDRCONFIG);
	}

	goto out;
	err2:
	free(space);
	err1:
	return 1;
	out:
	return 0;
}
