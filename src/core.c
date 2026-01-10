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
#include "rdns.h"
#include "mutex.h"

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
	char buff[1024*4];
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
		i = true_write(fd, &buff[wrote], size - wrote);
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
		if(ready != 1 || !(pfd[0].revents & POLLIN) || 1 != true_read(fd, &buff[i], 1))
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
#define BUFF_SIZE 1024  // used to read responses from proxies.
static int tunnel_to(int sock, ip_type ip, unsigned short port, proxy_type pt, char *user, char *pass) {
	char *dns_name = NULL;
	char hostnamebuf[MSG_LEN_MAX];
	size_t dns_len = 0;

	PFUNC();

	// we use ip addresses with 224.* to lookup their dns name in our table, to allow remote DNS resolution
	// the range 224-255.* is reserved, and it won't go outside (unless the app does some other stuff with
	// the results returned from gethostbyname et al.)
	// the hardcoded number 224 can now be changed using the config option remote_dns_subnet to i.e. 127
	if(!ip.is_v6 && proxychains_resolver >= DNSLF_RDNS_START && ip.addr.v4.octet[0] == remote_dns_subnet) {
		dns_len = rdns_get_host_for_ip(ip.addr.v4, hostnamebuf);
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
		case RAW_TYPE: {
			return SUCCESS;
		}
		break;
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

			if(len < 0 || len != true_send(sock, buff, len, 0))
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


/* Given a socket connected to a SOCKS5 proxy server, performs a UDP_ASSOCIATE handshake and returns BND_ADDR and BND_PORT if successfull.
Pass NULL dst_addr and dst_port to fill those fields with 0 if expected local addr and port for udp sending are unknown (see RFC1928) */
static int udp_associate(int sock, ip_type* dst_addr, unsigned short dst_port, ip_type* bnd_addr, unsigned short* bnd_port, char* user, char* pass){

	PFUNC();

	size_t ulen = strlen(user);
	size_t passlen = strlen(pass);

	if(ulen > 0xFF || passlen > 0xFF) {
		proxychains_write_log(LOG_PREFIX "error: maximum size of 255 for user/pass!\n");
		goto err;
	}

	int len;
	unsigned char buff[BUFF_SIZE];
	char ip_buf[INET6_ADDRSTRLEN];
	
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
	buff[buff_iter++] = 3;	// udp_associate
	buff[buff_iter++] = 0;	// reserved

	if(dst_addr) {
		int v6 = dst_addr->is_v6;
		buff[buff_iter++] = v6 ? 4 : 1;	// ip v4/v6
		memcpy(buff + buff_iter, dst_addr->addr.v6, v6?16:4);	// dest host
		buff_iter += v6?16:4;
		memcpy(buff + buff_iter, &dst_port, 2);	// dest port
		buff_iter += 2;
	} else {
		buff[buff_iter++] = 1;	//we put atyp = 1, should we put 0 ?
		buff[buff_iter++] = 0; // v4 byte1
		buff[buff_iter++] = 0; // v4 byte2
		buff[buff_iter++] = 0; // v4 byte3
		buff[buff_iter++] = 0; // v4 byte4
		buff[buff_iter++] = 0; // port byte1
		buff[buff_iter++] = 0; // port byte2
	}

	if(buff_iter != write_n_bytes(sock, (char *) buff, buff_iter))
		goto err;

	if(4 != read_n_bytes(sock, (char *) buff, 4))
		goto err;

	if(buff[0] != 5 || buff[1] != 0)
		goto err;


	switch (buff[3]) {
		case ATYP_V4:
			bnd_addr->is_v6 = 0;
			break;
		case ATYP_V6:
			bnd_addr->is_v6 = 1;
			break;
		case ATYP_DOM:
			PDEBUG("BND_ADDR in UDP_ASSOCIATE response should not be a domain name!\n");
			goto err;
			break;
		default:
			goto err;
	}
	len = bnd_addr->is_v6?16:4;

	if(len != read_n_bytes(sock, (char *) buff, len))
		goto err;

	memcpy(bnd_addr->addr.v6, buff,len);

	if(2 != read_n_bytes(sock, (char *) buff, 2))
		goto err;
	
	memcpy(bnd_port, buff, 2);

	return SUCCESS;
	
	err:
	return SOCKET_ERROR;
}

/* Fills buf with the SOCKS5 udp request header for the target dst_addr:dst_port*/
static int write_udp_header(socks5_addr dst_addr, unsigned short dst_port , char frag, char * buf, size_t buflen) {

	int size = 0;
	int v6 = dst_addr.atyp == ATYP_V6;

	if(dst_addr.atyp == ATYP_DOM){
		size = dst_addr.addr.dom.len;
	} else {
		size = v6?16:4;
	}

	if (buflen <= size) {
		return -1;
	}

	int buf_iter = 0;
	buf[buf_iter++] = 0;	// reserved
	buf[buf_iter++] = 0;	// reserved
	buf[buf_iter++] = frag;	// frag
	buf[buf_iter++] = dst_addr.atyp;	// atyp

	
	switch (dst_addr.atyp){
		case ATYP_V6:
		case ATYP_V4:
			memcpy(buf + buf_iter, dst_addr.addr.v6, v6?16:4);
			buf_iter += v6?16:4;
			break;
	
		case ATYP_DOM:
			buf[buf_iter++] = dst_addr.addr.dom.len;
			memcpy(buf + buf_iter, dst_addr.addr.dom.name, dst_addr.addr.dom.len);
			buf_iter += dst_addr.addr.dom.len;
			break;
	}

	memcpy(buf + buf_iter, &dst_port, 2);	// dest port
	buf_iter += 2;
	
	return buf_iter;
}


int read_udp_header(char * buf, size_t buflen, socks5_addr* src_addr, unsigned short* src_port, char* frag) {

	PFUNC();
	PDEBUG("buflen : %d\n", buflen);
	if (buflen < 5){
		PDEBUG("buffer too short to contain a UDP header\n");
		return -1;
	}

	int buf_iter = 0;
	buf_iter += 2; // first 2 bytes are reserved;
	*frag = buf[buf_iter++];
	src_addr->atyp = buf[buf_iter++];
	int v6;
	
	switch (src_addr->atyp)
	{
	case ATYP_DOM:
		PDEBUG("UDP header with ATYP_DOM addr type\n");
		src_addr->addr.dom.len = buf[buf_iter++];
		if(buflen < (5 + 2 + src_addr->addr.dom.len) ) {
			PDEBUG("buffer too short to read the UDP header\n");
			return -1;
		}
		memcpy(src_addr->addr.dom.name, buf + buf_iter, src_addr->addr.dom.len);
		buf_iter +=  src_addr->addr.dom.len;
		break;

	case ATYP_V4:
	case ATYP_V6:
		PDEBUG("UDP header with ATYP_V4/6 addr type\n");
		v6 = src_addr->atyp == ATYP_V6;
		if(buflen < (4 + 2 + v6?16:4) ){
			PDEBUG("buffer too short to read the UDP header\n");
			return -1;			
		}
		memcpy(src_addr->addr.v6, buf + buf_iter, v6?16:4);
		buf_iter += v6?16:4;
		cast_socks5addr_v4inv6_to_v4(src_addr);
		break;
	default:
		break;
	}

	memcpy(src_port, buf+buf_iter, 2);
	buf_iter += 2;

	return buf_iter;
}

size_t get_iov_total_len(struct iovec* iov, size_t iov_len){
	size_t n = 0;
	for(int i=0; i<iov_len; i++){
		n += iov[i].iov_len;
	}
	return n;
}

//Tries to write buff_len bytes from buff into the scatter-gather location described by iov and iov_len.
//Stops when all iov's buffers are full. Returns the number of bytes written 
size_t write_buf_to_iov(void* buff, size_t buff_len, struct iovec* iov, size_t iov_len){
	size_t written = 0;
	int i = 0;
	size_t min = 0;
	//size_t iov_total_len = get_iov_total_len(iov, iov_len);

	while( (written < buff_len) && (i < iov_len)){
		min = ((buff_len-written)<iov[i].iov_len)?(buff_len-written):iov[i].iov_len;
		memcpy(iov[i].iov_base, buff+written, min);
		written += min;
		i += 1;
	}
	return written;
}


size_t write_iov_to_buf(void* buff, size_t buff_len, struct iovec* iov, size_t iov_len){
	
	size_t written = 0;
	int i = 0;
	size_t min = 0;
	//size_t iov_total_len = get_iov_total_len(iov, iov_len);

	while( (written < buff_len) && (i < iov_len)){
		min = ((buff_len-written)<iov[i].iov_len)?(buff_len-written):iov[i].iov_len;
		memcpy(buff+written, iov[i].iov_base, min);
		written += min;
		i += 1;
	}
	return written;
}

void cast_socks5addr_v4inv6_to_v4(socks5_addr* addr){
	if( (addr->atyp == ATYP_V6) && !memcmp(addr->addr.v6, "\0\0\0\0\0\0\0\0\0\0\xff\xff", 12)){
		PDEBUG("casting v4inv6 address to v4 address\n");
		addr->atyp=ATYP_V4;
		memcpy(addr->addr.v4.octet, addr->addr.v6+12, 4);
	}
}

int compare_iptype_sockaddr(ip_type addr1, struct sockaddr* addr2){
	if(addr1.is_v6 && (((struct sockaddr_in6 *)addr2)->sin6_family == AF_INET6)){
		//Both are IPv6
		return !memcmp(((struct sockaddr_in6 *)addr2)->sin6_addr.s6_addr, addr1.addr.v6, 16);
	} else if(!addr1.is_v6 && (((struct sockaddr_in *)addr2)->sin_family == AF_INET)){
		//Both are IPv4
		return ((uint32_t)(((struct sockaddr_in *)addr2)->sin_addr.s_addr) == addr1.addr.v4.as_int);
	} else {
		// Not the same address type
		return 0;
	}
}

int compare_socks5_addr_iptype(socks5_addr addr1, ip_type addr2){
	PFUNC();
	if(addr1.atyp == ATYP_DOM){
		//addr1 is a domain name
		return 0;
	}

	if((addr1.atyp == ATYP_V6) && addr2.is_v6){
		//Both are IPv6
		return !memcmp(addr1.addr.v6, addr2.addr.v6, 16);
	} else if((addr1.atyp == ATYP_V4) && !addr2.is_v6){
		//Both are IPv4
		return (addr1.addr.v4.as_int == addr2.addr.v4.as_int);
	} else {
		// Not the same address type
		return 0;
	}
}

int is_from_chain_head(udp_relay_chain chain, struct sockaddr* src_addr){

	if(compare_iptype_sockaddr(chain.head->bnd_addr, src_addr)){
		return (chain.head->bnd_port == ((struct sockaddr_in*)src_addr)->sin_port); 
	}
	return 0;
}



int decapsulate_check_udp_packet(void* in_buffer, size_t in_buffer_len, udp_relay_chain chain, socks5_addr* src_addr, unsigned short* src_port, void** udp_data){
	
	PFUNC();
	// Go through the whole proxy chain, decapsulate each header and check that the addresses match

	udp_relay_node * tmp = chain.head;
	int read = 0;
	int rc = 0;
	socks5_addr header_addr;
	unsigned short header_port;
	char header_frag;
	while (tmp->next != NULL)
	{
		rc = read_udp_header(in_buffer+read, in_buffer_len-read, &header_addr, &header_port, &header_frag );
		if(-1 == rc){
			PDEBUG("error reading UDP header\n");
			return -1;
		}
		read += rc;

		if(header_frag != 0x00){
			printf("WARNING: received UDP packet with frag != 0 while fragmentation is unsupported.\n");
		}

		if(!compare_socks5_addr_iptype(header_addr, tmp->next->bnd_addr)){
			PDEBUG("UDP header addr is not equal to proxy node addr, dropping packet\n");
			return -1;
		}

		if(tmp->next->bnd_port != header_port){
			PDEBUG("UDP header port is not equal to proxy node port, dropping packet\n");
			return -1;
		}

		PDEBUG("UDP header's addr and port correspond to proxy node's addr and port\n");
		tmp = tmp->next;
	}

	PDEBUG("all UDP headers validated\n");


	// Decapsulate the last header. No checks needed here, just pass the source addr and port as return values
	rc = read_udp_header(in_buffer+read, in_buffer_len-read, src_addr, src_port, &header_frag);
	if(-1 == rc){
		PDEBUG("error reading UDP header\n");
		return -1;
	}
	read += rc;

	if(header_frag != 0x00){
		printf("WARNING: received UDP packet with frag != 0 while fragmentation is unsupported.\n");
	}


	// Point udp_data to the position of the UDP data inside in_buffer
	*udp_data = in_buffer+read;
	
	return 0;
}

//Takes an in_buffer of size in_buffer_len, checks that all UDP headers are correct (against chain), fills src_ip and src_port with address of the peer sending the packet through the relay, and fills udp_data with the address of the udp data inside in_buff
int unsocksify_udp_packet(void* in_buffer, size_t in_buffer_len, udp_relay_chain chain, ip_type* src_ip, unsigned short* src_port, void** udp_data){
	PFUNC();
	// Decapsulate all the UDP headers and check that the packet came from the right proxy nodes
	int rc;
	socks5_addr src_addr;
	rc = decapsulate_check_udp_packet(in_buffer, in_buffer_len, chain, &src_addr, src_port, udp_data);
	if(rc != SUCCESS){
		PDEBUG("error decapsulating the packet\n");
		return -1;
	}
	PDEBUG("all UDP headers decapsulated and validated\n");

	// If the innermost UDP header (containing the address of the final target) is of type ATYP_DOM, perform a 
	// reverse mapping to hand the 224.X.X.X IP to the client application
	
	if(src_addr.atyp == ATYP_DOM){ 
		PDEBUG("Fetching matching IP for hostname\n");
		DUMP_BUFFER(src_addr.addr.dom.name,src_addr.addr.dom.len);
		ip_type4 tmp_ip = IPT4_INVALID;
		char host_string[256];
		memcpy(host_string, src_addr.addr.dom.name, src_addr.addr.dom.len);
		host_string[src_addr.addr.dom.len] = 0x00;

		tmp_ip = rdns_get_ip_for_host(host_string, src_addr.addr.dom.len);
		if(tmp_ip.as_int == -1){
			PDEBUG("error getting ip for host\n");
			return -1;
		}
		src_addr.atyp = ATYP_V4;
		src_addr.addr.v4.as_int = tmp_ip.as_int;
	
	}
	
	src_ip->is_v6 = (src_addr.atyp == ATYP_V6); 
	if(src_ip->is_v6){
		memcpy(src_ip->addr.v6, src_addr.addr.v6, 16);
	} else{
		src_ip->addr.v4.as_int = src_addr.addr.v4.as_int;
	}
	
	return 0;
}


int encapsulate_udp_packet(udp_relay_chain chain, socks5_addr dst_addr, unsigned short dst_port, void* buffer, size_t* buffer_len){
	
	PFUNC();

	unsigned int written = 0;
	unsigned int offset = 0;
	udp_relay_node * tmp = chain.head;
	
	while ((tmp->next != NULL) && (written < *buffer_len))
	{
		socks5_addr tmpaddr;
		tmpaddr.atyp = (tmp->next)->bnd_addr.is_v6?ATYP_V6:ATYP_V4;
		memcpy(tmpaddr.addr.v6, (tmp->next)->bnd_addr.addr.v6, (tmp->next)->bnd_addr.is_v6?16:4);

		written = write_udp_header(tmpaddr, (tmp->next)->bnd_port, 0, buffer+offset, *buffer_len - offset);
		if (written == -1){
			PDEBUG("error write_udp_header\n");
			return -1; 
		}
		offset += written;

		tmp = tmp->next;
	}

	written = write_udp_header(dst_addr, dst_port, 0, buffer+offset, *buffer_len-offset);
	if (written == -1){
		PDEBUG("error write_udp_header\n");
		return -1;
	}
	offset += written;

	*buffer_len = offset;

	return 0;
}

int socksify_udp_packet(void* udp_data, size_t udp_data_len, udp_relay_chain chain, ip_type dst_ip, unsigned short dst_port, void* buffer, size_t* buffer_len){
	
	PFUNC();
	if (chain.head == NULL ){ 
		PDEBUG("provided chain is empty\n");
		return -1;
	}

	char *dns_name = NULL;
	char hostnamebuf[MSG_LEN_MAX];
	size_t dns_len = 0;
	socks5_addr dst_addr;
	// we use ip addresses with 224.* to lookup their dns name in our table, to allow remote DNS resolution
	// the range 224-255.* is reserved, and it won't go outside (unless the app does some other stuff with
	// the results returned from gethostbyname et al.)
	// the hardcoded number 224 can now be changed using the config option remote_dns_subnet to i.e. 127
	if(!dst_ip.is_v6 && proxychains_resolver >= DNSLF_RDNS_START && dst_ip.addr.v4.octet[0] == remote_dns_subnet) {
		dst_addr.atyp = ATYP_DOM;
		dns_len = rdns_get_host_for_ip(dst_ip.addr.v4, dst_addr.addr.dom.name);
		PDEBUG("dnslen: %d\n", dns_len);
		if(!dns_len) return -1;
		else dns_name = dst_addr.addr.dom.name;
		dst_addr.addr.dom.len = dns_len & 0xFF;
		PDEBUG("dnslen in struct: %d\n", dst_addr.addr.dom.len);
		
	} else {
		if(dst_ip.is_v6){
			dst_addr.atyp =  ATYP_V6;
			memcpy(dst_addr.addr.v6, dst_ip.addr.v6, 16);
		 
		} else {
			dst_addr.atyp = ATYP_V4;
			memcpy(dst_addr.addr.v4.octet, dst_ip.addr.v4.octet, 4);
		}
	}
	
	PDEBUG("host dns %s\n", dns_name ? dns_name : "<NULL>");


	// Write all the UDP headers into the provided buffer
	int rc;
	size_t tmp_buffer_len = *buffer_len;
	rc = encapsulate_udp_packet(chain, dst_addr, dst_port, buffer, &tmp_buffer_len);
	if(rc != SUCCESS){
		PDEBUG("error encapsulate_udp_packet()\n");
		return -1;

	}


	// Append UDP data in the remaining space of the buffer
	size_t min = (udp_data_len>(buffer_len-tmp_buffer_len))?(buffer_len-tmp_buffer_len):udp_data_len;
	memcpy(buffer + tmp_buffer_len, udp_data, min);

	*buffer_len = tmp_buffer_len + min;

	return 0;

}


#define TP " ... "
#define DT "Dynamic chain"
#define ST "Strict chain"
#define RT "Random chain"
#define RRT "Round Robin chain"
#define UDPC "UDP_ASSOCIATE tcp socket chain"

static int start_chain(int *fd, proxy_data * pd, char *begin_mark) {
	PFUNC();
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
	if(*fd != -1) {
		true_close(*fd);
		*fd = -1;
	}
	return SOCKET_ERROR;
}

static proxy_data *select_proxy(select_type how, proxy_data * pd, unsigned int proxy_count, unsigned int *offset) {
	PFUNC();
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


static int chain_step(int *ns, proxy_data * pfrom, proxy_data * pto) {
	int retcode = -1;
	char *hostname, *errmsg = 0;
	char hostname_buf[MSG_LEN_MAX];
	char ip_buf[INET6_ADDRSTRLEN];
	int v6 = pto->ip.is_v6;

	PFUNC();

	if(!v6 && proxychains_resolver >= DNSLF_RDNS_START && pto->ip.addr.v4.octet[0] == remote_dns_subnet) {
		if(!rdns_get_host_for_ip(pto->ip.addr.v4, hostname_buf)) goto usenumericip;
		else hostname = hostname_buf;
	} else {
	usenumericip:
		if(!inet_ntop(v6?AF_INET6:AF_INET,pto->ip.addr.v6,ip_buf,sizeof ip_buf)) {
			pto->ps = DOWN_STATE;
			errmsg = "<--ip conversion error!\n";
			retcode = SOCKET_ERROR;
			goto err;
		}
		hostname = ip_buf;
	}

	proxychains_write_log(TP " %s:%d ", hostname, htons(pto->port));
	retcode = tunnel_to(*ns, pto->ip, pto->port, pfrom->pt, pfrom->user, pfrom->pass);
	switch (retcode) {
		case SUCCESS:
			pto->ps = BUSY_STATE;
			break;
		case BLOCKED:
			pto->ps = BLOCKED_STATE;
			errmsg = "<--denied\n";
			goto err;
		case SOCKET_ERROR:
			pto->ps = DOWN_STATE;
			errmsg = "<--socket error or timeout!\n";
			goto err;
	}
	return retcode;
err:
	if(errmsg) proxychains_write_log(errmsg);
	if(*ns != -1) true_close(*ns);
	*ns = -1;
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
	unsigned int looped = 0; // went back to start of list in RR mode
	unsigned int rr_loop_max = 14;

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
				if(SUCCESS != chain_step(&ns, p1, p2)) {
					PDEBUG("GOTO AGAIN 1\n");
					goto again;
				}
				p1 = p2;
			}
			//proxychains_write_log(TP);
			p3->ip = target_ip;
			p3->port = target_port;
			if(SUCCESS != chain_step(&ns, p1, p3))
				goto error;
			break;

		case ROUND_ROBIN_TYPE:
			alive_count = calc_alive(pd, proxy_count);
			offset = proxychains_proxy_offset;
			if(alive_count < max_chain)
				goto error_more;
			PDEBUG("1:rr_offset = %d\n", offset);
			/* Check from current RR offset til end */
			for (;rc != SUCCESS;) {
				if (!(p1 = select_proxy(FIFOLY, pd, proxy_count, &offset))) {
					/* We've reached the end of the list, go to the start */
 					offset = 0;
					looped++;
					if (looped > rr_loop_max) {
						proxychains_proxy_offset = 0;
						goto error_more;
					} else {
						PDEBUG("rr_type all proxies down, release all\n");
						release_all(pd, proxy_count);
						/* Each loop we wait 10ms more */
						usleep(10000 * looped);
						continue;
					}
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
				} else if(SUCCESS != chain_step(&ns, p1, p2)) {
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
			if(SUCCESS != chain_step(&ns, p1, p3))
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
				if(SUCCESS != chain_step(&ns, p1, p2)) {
					PDEBUG("chain_step failed\n");
					goto error_strict;
				}
				p1 = p2;
			}
			//proxychains_write_log(TP);
			p3->ip = target_ip;
			p3->port = target_port;
			if(SUCCESS != chain_step(&ns, p1, p3))
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
				if(SUCCESS != chain_step(&ns, p1, p2)) {
					PDEBUG("GOTO AGAIN 2\n");
					goto again;
				}
				p1 = p2;
			}
			//proxychains_write_log(TP);
			p3->ip = target_ip;
			p3->port = target_port;
			if(SUCCESS != chain_step(&ns, p1, p3))
				goto error;

	}

	proxychains_write_log(TP " OK\n");
	dup2(ns, sock);
	true_close(ns);
	return 0;
	error:
	if(ns != -1)
		true_close(ns);
	errno = ECONNREFUSED;	// for nmap ;)
	return -1;

	error_more:
	proxychains_write_log("\n!!!need more proxies!!!\n");
	error_strict:
	PDEBUG("error\n");
	
	release_all(pd, proxy_count);
	if(ns != -1)
		true_close(ns);
	errno = ETIMEDOUT;
	return -1;
}


int add_node_to_chain(proxy_data * pd, udp_relay_chain * chain){
	PFUNC();
	// Allocate memory for the new node structure
	udp_relay_node * new_node = NULL;
	if(NULL == (new_node = (udp_relay_node *)malloc(sizeof(udp_relay_node)))){
		PDEBUG("error malloc new node\n");
		return -1;
	}
	new_node->next = NULL;

	
	udp_relay_node * tmp = chain->head;

	if(tmp == NULL){ // Means new_node is the first node to be created
		chain->head = new_node;
		new_node->prev = NULL;
	} else {
		// Moving to the end of the current chain
		while(tmp->next != NULL){
			tmp = tmp->next;
		}
		// Adding the new node at the end
		tmp->next = new_node;
		new_node->prev = tmp;
	}
	

	// Initializing the new node
	new_node->pd.ip = pd->ip;
	new_node->pd.port = pd->port;
	new_node->pd.pt = pd->pt;
	new_node->pd.ps = pd->ps;
	strcpy(new_node->pd.user, pd->user);
	strcpy(new_node->pd.pass, pd->pass);

	// Connecting the new node tcp_socketfd to the associated proxy through the current chain
	//
	tmp = chain->head;
	//    First connect to the chain head
	if(SUCCESS != start_chain(&(new_node->tcp_sockfd), &(tmp->pd), UDPC)){
		PDEBUG("start_chain failed\n");
		new_node->tcp_sockfd = -1;
		goto err;
	}
	//   Connect to the rest of the chain
	while(tmp->next != NULL){
		if(SUCCESS != chain_step(&(new_node->tcp_sockfd), &(tmp->pd), &(tmp->next->pd))){
			PDEBUG("chain step failed\n");
			new_node->tcp_sockfd = -1;
			goto err;
		}
		tmp = tmp->next;
	}

	// Performing UDP_ASSOCIATE handshake in order to fill the new node BND_ADDR and BND_PORT
	if(SUCCESS != udp_associate(new_node->tcp_sockfd, NULL, NULL, &(new_node->bnd_addr), &(new_node->bnd_port), new_node->pd.user, new_node->pd.pass)){
		PDEBUG("udp_associate failed\n");
		goto err;
	}

	char ip_buf[INET6_ADDRSTRLEN];
	proxychains_write_log(" --> Node[%s:%i] open\n", inet_ntop(new_node->bnd_addr.is_v6?AF_INET6:AF_INET, new_node->bnd_addr.is_v6?(void*)new_node->bnd_addr.addr.v6:(void*)new_node->bnd_addr.addr.v4.octet, ip_buf, sizeof(ip_buf))  , ntohs(new_node->bnd_port));
	PDEBUG("new node added and open to relay UDP packets\n");
	return SUCCESS;

	err:
	// Ensure new node tcp socket is closed
	if(new_node->tcp_sockfd != -1){
		true_close(new_node->tcp_sockfd);
	}

	// Remove the new node from the chain
	if(new_node->prev == NULL){ // means new_node is the only node in chain
		chain->head = NULL;
	} else{
		(new_node->prev)->next  = NULL;
	}
	

	// Free memory
	free(new_node);

	return -1;
}

int free_relay_chain_contents(udp_relay_chain* chain){
	if(NULL != chain->connected_peer_addr){
		free(chain->connected_peer_addr);
		chain->connected_peer_addr = NULL; 
	}

	if(chain->head == NULL){
		return SUCCESS;
	}
	
	udp_relay_node * current = chain->head;
	udp_relay_node * next = NULL;
	
	while(current != NULL){
		next = current->next;

		true_close(current->tcp_sockfd);
		free(current);

		current = next;
	}
	chain->head = NULL;

	return SUCCESS;
}

udp_relay_chain * open_relay_chain(proxy_data *pd, unsigned int proxy_count, chain_type ct, unsigned int max_chains){
	
	PFUNC();
	// Allocate memory for the new relay chain
	udp_relay_chain * new_chain = NULL;
	if(NULL == (new_chain = (udp_relay_chain *)malloc(sizeof(udp_relay_chain)))){
		PDEBUG("error malloc new chain\n");
		return NULL;
	}

	new_chain->head = NULL;
	new_chain->sockfd = -1;
	new_chain->connected_peer_addr = NULL;
	new_chain->connected_peer_addr_len = -1;

	
	unsigned int alive_count = 0;
	unsigned int offset = 0;
	proxy_data *p1;


	switch (ct)
	{
	case DYNAMIC_TYPE:
		PDEBUG("DYNAMIC_TYPE not yet supported for UDP\n");
		goto error; 
		break;
	case ROUND_ROBIN_TYPE:
		PDEBUG("ROUND_ROBIN_TYPE not yet supported for UDP\n");
		goto error; 
		break;
	case STRICT_TYPE:
		alive_count = calc_alive(pd, proxy_count);
		offset = 0;
		PDEBUG("opening STRICT_TYPE relay chain, alive_count=%d, offset=%d\n", alive_count, offset);
		while((p1 = select_proxy(FIFOLY, pd, proxy_count, &offset))) {
			if(SUCCESS != add_node_to_chain(p1, new_chain)) {
				PDEBUG("add_node_to_chain failed\n");
				p1->ps = BLOCKED_STATE;
				goto error;
			}
			p1->ps = BUSY_STATE;	
		}
		return new_chain;

		break;
	case RANDOM_TYPE:
		PDEBUG("RANDOM_TYPE not yet supported for UDP\n");
		goto error; 
		break;
	default:
		break;
	}

	error:
	PDEBUG("error\n");
	release_all(pd, proxy_count);
	free_relay_chain_contents(new_chain);
	free(new_chain);
	errno = ETIMEDOUT;
	return NULL;
}

// Checks the address family of addr, allocates a matching structure and keeps a pointer to it in the chain structure to store the address of the connected peer
void set_connected_peer_addr(udp_relay_chain* chain, struct sockaddr* addr, socklen_t addrlen){
	
	sa_family_t fam = ((struct sockaddr_in*)addr)->sin_family;
	int v6 = fam == AF_INET6;



	if(v6){
		struct sockaddr_in6* old_addr6 = (struct sockaddr_in6*)addr;
		struct sockaddr_in6* new_addr6 = NULL;
		if(NULL == (new_addr6 = (struct sockaddr_in6*)malloc(sizeof(struct sockaddr_in6)))){
			PDEBUG("error malloc\n");
			return -1;
		}

		new_addr6->sin6_family = old_addr6->sin6_family;
		new_addr6->sin6_port = old_addr6->sin6_port;
		memcpy(new_addr6->sin6_addr.s6_addr, old_addr6->sin6_addr.s6_addr, 16);

		chain->connected_peer_addr = (struct sockaddr*)new_addr6;
		chain->connected_peer_addr_len = sizeof(struct sockaddr_in6);

	} else{
		struct sockaddr_in* old_addr = (struct sockaddr_in*)addr;
		struct sockaddr_in* new_addr = NULL;
		if(NULL == (new_addr = (struct sockaddr_in*)malloc(sizeof(struct sockaddr_in)))){
			PDEBUG("error malloc\n"); 
			return -1;
		}

		new_addr->sin_family = old_addr->sin_family;
		new_addr->sin_port = old_addr->sin_port;
		new_addr->sin_addr.s_addr = old_addr->sin_addr.s_addr;

		chain->connected_peer_addr = (struct sockaddr*)new_addr;
		chain->connected_peer_addr_len = sizeof(struct sockaddr_in);
	}
}


void add_relay_chain(udp_relay_chain_list* chains_list, udp_relay_chain* new_chain){

	new_chain->next = NULL;

	if(chains_list->tail == NULL){ // The current list is empty, set head and tail to the new chain
		chains_list->head = new_chain;
		chains_list->tail = new_chain;
		new_chain->prev = NULL;
	} else {
		// Add the new chain at the end
		(chains_list->tail)->next = new_chain;
		new_chain->prev = chains_list->tail;
		chains_list->tail = new_chain;
	}
}

void del_relay_chain(udp_relay_chain_list* chains_list, udp_relay_chain* chain){
	if(chain == chains_list->head){
		if(chain->next == NULL){
			free(chain);
			chains_list->head = NULL;
			chains_list->tail = NULL;
		}else{
			chains_list->head = chain->next;
			chains_list->head->prev = NULL;
			free(chain);
		}
	} else if (chain == chains_list->tail){
		chains_list->tail = chain->prev;
		chains_list->tail->next = NULL;
		free(chain);
	} else {
		chain->next->prev = chain->prev;
		chain->prev->next = chain->next;
		free(chain);
	}
}

udp_relay_chain* get_relay_chain(udp_relay_chain_list chains_list, int sockfd){
	udp_relay_chain* tmp = chains_list.head;
	while(tmp != NULL){
		if(tmp->sockfd == sockfd){
			break;
		}
		tmp = tmp->next;
	}
	return tmp;
}

static pthread_mutex_t servbyname_lock;
void core_initialize(void) {
	MUTEX_INIT(&servbyname_lock);
}

void core_unload(void) {
	MUTEX_DESTROY(&servbyname_lock);
}

static void gethostbyname_data_setstring(struct gethostbyname_data* data, char* name) {
	snprintf(data->addr_name, sizeof(data->addr_name), "%s", name);
	data->hostent_space.h_name = data->addr_name;
}

extern ip_type4 hostsreader_get_numeric_ip_for_name(const char* name);
struct hostent* proxy_gethostbyname_old(const char *name)
{
	static struct hostent hostent_space;
	static in_addr_t resolved_addr;
	static char* resolved_addr_p;
	static char addr_name[256];

	int pipe_fd[2];
	char buff[256];
	in_addr_t addr;
	pid_t pid;
	int status, ret;
	size_t l;
	struct hostent* hp;

	hostent_space.h_addr_list = &resolved_addr_p;
	*hostent_space.h_addr_list = (char*)&resolved_addr;
	resolved_addr = 0;

	if(pc_isnumericipv4(name)) {
		strcpy(buff, name);
		goto got_buff;
	}

	gethostname(buff,sizeof(buff));
	if(!strcmp(buff,name))
		goto got_buff;

	memset(buff, 0, sizeof(buff));

	// TODO: this works only once, so cache it  ...
	// 	 later
	while ((hp=gethostent()))
		if (!strcmp(hp->h_name,name))
			return hp;
#ifdef HAVE_PIPE2
	ret = pipe2(pipe_fd, O_CLOEXEC);
#else
	ret = pipe(pipe_fd);
	if(ret == 0) {
		fcntl(pipe_fd[0], F_SETFD, FD_CLOEXEC);
		fcntl(pipe_fd[1], F_SETFD, FD_CLOEXEC);
	}
#endif

	if(ret)
		goto err;
	pid = fork();
	switch(pid) {

		case 0: // child
			proxychains_write_log("|DNS-request| %s \n", name);
			true_close(pipe_fd[0]);
			dup2(pipe_fd[1],1);
			true_close(pipe_fd[1]);

		//	putenv("LD_PRELOAD=");
			execlp("proxyresolv","proxyresolv",name,NULL);
			perror("can't exec proxyresolv");
			exit(2);

		case -1: //error
			true_close(pipe_fd[0]);
			true_close(pipe_fd[1]);
			perror("can't fork");
			goto err;

		default:
			true_close(pipe_fd[1]);
			waitpid(pid, &status, 0);
			buff[0] = 0;
			true_read(pipe_fd[0],&buff,sizeof(buff));
			true_close(pipe_fd[0]);
got_buff:
			l = strlen(buff);
			if (!l) goto err_dns;
			if (buff[l-1] == '\n') buff[l-1] = 0;
			addr = inet_addr(buff);
			if (addr == (in_addr_t) (-1))
				goto err_dns;
			memcpy(*(hostent_space.h_addr_list),
						&addr ,sizeof(struct in_addr));
			hostent_space.h_name = addr_name;
			snprintf(addr_name, sizeof addr_name, "%s", buff);
			hostent_space.h_length = sizeof (in_addr_t);
			hostent_space.h_addrtype = AF_INET;
	}
	proxychains_write_log("|DNS-response| %s is %s\n",
			name, inet_ntoa(*(struct in_addr*)&addr));
	return &hostent_space;
err_dns:
	proxychains_write_log("|DNS-response|: %s lookup error\n", name);
err:
	return NULL;
}

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

	if(pc_isnumericipv4(name)) {
		data->resolved_addr = inet_addr(name);
		goto retname;
	}

	gethostname(buff, sizeof(buff));

	if(!strcmp(buff, name)) {
		data->resolved_addr = inet_addr(buff);
		if(data->resolved_addr == (in_addr_t) (-1))
			data->resolved_addr = (in_addr_t) (IPT4_LOCALHOST.as_int);
		goto retname;
	}

	// this iterates over the "known hosts" db, usually /etc/hosts
	ip_type4 hdb_res = hostsreader_get_numeric_ip_for_name(name);
	if(hdb_res.as_int != IPT4_INVALID.as_int) {
		data->resolved_addr = hdb_res.as_int;
		goto retname;
	}
	
	data->resolved_addr = rdns_get_ip_for_host((char*) name, strlen(name)).as_int;
	if(data->resolved_addr == (in_addr_t) IPT4_INVALID.as_int) return NULL;

	retname:

	gethostbyname_data_setstring(data, (char*) name);
	
	PDEBUG("return hostent space\n");
	
	return &data->hostent_space;
}

struct addrinfo_data {
	struct addrinfo addrinfo_space;
	struct sockaddr_storage sockaddr_space;
	char addr_name[256];
};

void proxy_freeaddrinfo(struct addrinfo *res) {
	PFUNC();
	free(res);
}

static int mygetservbyname_r(const char* name, const char* proto, struct servent* result_buf,
			   char* buf, size_t buflen, struct servent** result) {
	PFUNC();
#ifdef HAVE_GNU_GETSERVBYNAME_R
	PDEBUG("using host getservbyname_r\n");
	return getservbyname_r(name, proto, result_buf, buf, buflen, result);
#endif
	struct servent *res;
	int ret;
	(void) buf; (void) buflen;
	MUTEX_LOCK(&servbyname_lock);
	res = getservbyname(name, proto);
	if(res) {
		*result_buf = *res;
		*result = result_buf;
		ret = 0;
	} else {
		*result = NULL;
		ret = ENOENT;
	}
	MUTEX_UNLOCK(&servbyname_lock);
	return ret;
}

static int looks_like_numeric_ipv6(const char *node)
{
	if(!strchr(node, ':')) return 0;
	const char* p= node;
	while(1) switch(*(p++)) {
		case 0: return 1;
		case ':': case '.':
		case '0': case '1': case '2': case '3': case '4':
		case '5': case '6': case '7': case '8': case '9':
		case 'A': case 'B': case 'C': case 'D': case 'E': case 'F':
		case 'a': case 'b': case 'c': case 'd': case 'e': case 'f':
			break;
		default: return 0;
	}
}

static int my_inet_aton(const char *node, struct addrinfo_data* space)
{
	int ret;
	((struct sockaddr_in *) &space->sockaddr_space)->sin_family = AF_INET;
	ret = inet_aton(node, &((struct sockaddr_in *) &space->sockaddr_space)->sin_addr);
	if(ret || !looks_like_numeric_ipv6(node)) return ret;
	ret = inet_pton(AF_INET6, node, &((struct sockaddr_in6 *) &space->sockaddr_space)->sin6_addr);
	if(ret) ((struct sockaddr_in6 *) &space->sockaddr_space)->sin6_family = AF_INET6;
	return ret;
}

int proxy_getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res) {
	struct gethostbyname_data ghdata;
	struct addrinfo_data *space;
	struct servent *se = NULL;
	struct hostent *hp = NULL;
	struct servent se_buf;
	struct addrinfo *p;
	char buf[1024];
	int port, af = AF_INET;

	PDEBUG("proxy_getaddrinfo node:%s service: %s, flags: %d\n",
		node?node:"",service?service:"",hints?(int)hints->ai_flags:0);

	space = calloc(1, sizeof(struct addrinfo_data));
	if(!space) return EAI_MEMORY;

	if(node && !my_inet_aton(node, space)) {
		/* some folks (nmap) use getaddrinfo() with AI_NUMERICHOST to check whether a string
		   containing a numeric ip was passed. we must return failure in that case. */
		if(hints && (hints->ai_flags & AI_NUMERICHOST)) {
err_nn:
			free(space);
			return EAI_NONAME;
		}
		if(proxychains_resolver == DNSLF_FORKEXEC)
			hp = proxy_gethostbyname_old(node);
		else
			hp = proxy_gethostbyname(node, &ghdata);

		if(hp)
			memcpy(&((struct sockaddr_in *) &space->sockaddr_space)->sin_addr,
			       *(hp->h_addr_list), sizeof(in_addr_t));
		else
			goto err_nn;
	} else if(node) {
		af = ((struct sockaddr_in *) &space->sockaddr_space)->sin_family;
	} else if(!node && !(hints->ai_flags & AI_PASSIVE)) {
		af = ((struct sockaddr_in *) &space->sockaddr_space)->sin_family = AF_INET;
		memcpy(&((struct sockaddr_in *) &space->sockaddr_space)->sin_addr,
		       "\177\0\0\1", 4);
	}
	if(service) mygetservbyname_r(service, NULL, &se_buf, buf, sizeof(buf), &se);

	port = se ? se->s_port : htons(atoi(service ? service : "0"));
	if(af == AF_INET)
		((struct sockaddr_in *) &space->sockaddr_space)->sin_port = port;
	else
		((struct sockaddr_in6 *) &space->sockaddr_space)->sin6_port = port;

	*res = p = &space->addrinfo_space;
	assert((size_t)p == (size_t) space);

	p->ai_addr = (void*) &space->sockaddr_space;
	if(node)
		snprintf(space->addr_name, sizeof(space->addr_name), "%s", node);
	p->ai_canonname = space->addr_name;
	p->ai_next = NULL;
	p->ai_family = space->sockaddr_space.ss_family = af;
	p->ai_addrlen = af == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);

	if(hints) {
		p->ai_socktype = hints->ai_socktype;
		p->ai_flags = hints->ai_flags;
		p->ai_protocol = hints->ai_protocol;
		if(!p->ai_socktype && p->ai_protocol == IPPROTO_TCP)
			p->ai_socktype = SOCK_STREAM;
	} else {
#ifndef AI_V4MAPPED
#define AI_V4MAPPED 0
#endif
		p->ai_flags = (AI_V4MAPPED | AI_ADDRCONFIG);
	}
	return 0;
}
