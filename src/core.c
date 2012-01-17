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
#include <sys/poll.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <time.h>
#include <sys/time.h>
#include <stdarg.h>
#ifdef THREAD_SAFE
#include <pthread.h>
pthread_mutex_t internal_ips_lock;
#endif

#include "core.h"
#include "common.h"

extern int tcp_read_time_out;
extern int tcp_connect_time_out;
extern int proxychains_quiet_mode;

internal_ip_lookup_table internal_ips = {0, 0, NULL};


uint32_t dalias_hash(char* s0) {
	unsigned char* s = (void*) s0;
	uint_fast32_t h = 0;
	while (*s) {
		h = 16*h + *s++;
		h ^= h>>24 & 0xf0;
	}
	return h & 0xfffffff;
}

uint32_t index_from_internal_ip(ip_type internalip) {
	ip_type tmp = internalip;
	uint32_t ret;
	ret = tmp.octet[3] + (tmp.octet[2] << 8) + (tmp.octet[1] << 16);
	ret -= 1;
	return ret;
}

char* string_from_internal_ip(ip_type internalip) {
	char* res = NULL;
#ifdef THREAD_SAFE
	pthread_mutex_lock(&internal_ips_lock);
#endif
	uint32_t index = index_from_internal_ip(internalip);
	if(index < internal_ips.counter)
		res = internal_ips.list[index]->string;
#ifdef THREAD_SAFE
	pthread_mutex_unlock(&internal_ips_lock);
#endif
	return res;
}

in_addr_t make_internal_ip(uint32_t index) {
	ip_type ret;
	index++; // so we can start at .0.0.1
	if(index > 0xFFFFFF) return (in_addr_t) -1;
	ret.octet[0] = 224;
	ret.octet[1] = (index & 0xFF0000) >> 16;
	ret.octet[2] = (index & 0xFF00) >> 8;
	ret.octet[3] = index & 0xFF;
	return (in_addr_t) ret.as_int;
}

static const char base64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int poll_retry(struct pollfd *fds, nfds_t nfsd, int timeout) 
{
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
		time_elapsed =  ((tv.tv_sec - start_time.tv_sec) * 1000 + (tv.tv_usec - start_time.tv_usec) / 1000);
		//printf("Time elapsed %d\n", time_elapsed);
		time_remain = timeout - time_elapsed;
	} while (ret == -1 && errno == EINTR && time_remain > 0);
	
	//if (ret == -1)
	//printf("Return %d %d %s\n", ret, errno, strerror(errno));
	return ret;
}


static void encode_base_64(char* src,char* dest,int max_len)
{
	int n,l,i;
 	l=strlen(src);
	max_len=(max_len-1)/4;
	for ( i=0;i<max_len;i++,src+=3,l-=3)
	{
		switch (l) {
		case 0:
			break;
		case 1:
			n=src[0] << 16;
			*dest++=base64[(n >> 18) & 077];
			*dest++=base64[(n >> 12) & 077];
			*dest++='=';
			*dest++='=';
			break;
		case 2:
			n=src[0] << 16 | src[1] << 8;
			*dest++=base64[(n >> 18) & 077];
			*dest++=base64[(n >> 12) & 077];
			*dest++=base64[(n >> 6) & 077];
			*dest++='=';
			break;
		default:
			n=src[0] << 16 | src[1] << 8 | src[2];
			*dest++=base64[(n >> 18) & 077];
			*dest++=base64[(n >> 12) & 077];
			*dest++=base64[(n >> 6) & 077];
			*dest++=base64[n & 077];
		}
		if (l<3) break;
	}
	*dest++=0;
}

#define LOG_BUFF 1024*20

int proxychains_write_log(char *str,...)
{
	char buff[LOG_BUFF];
	va_list arglist;
	FILE * log_file;
	log_file=stderr;
	if (!proxychains_quiet_mode) {
		va_start(arglist,str);
		vsprintf(buff,str,arglist);
		va_end(arglist);
		fprintf(log_file,"%s",buff);
		fflush(log_file);
	}
	return EXIT_SUCCESS;
}

static int write_n_bytes(int fd,char *buff,size_t size)
{
	int i=0;
	size_t wrote=0;
	for(;;)	{
		i = write(fd,&buff[wrote],size-wrote);
		if(i<=0)
			return i;
		wrote += i;
		if(wrote==size)
			return wrote;
	}
}

static int read_n_bytes(int fd,char *buff, size_t size)
{
	int ready;
	size_t i;
	struct pollfd pfd[1];

	pfd[0].fd=fd;
	pfd[0].events=POLLIN;
	for(i=0; i < size; i++) {  
		pfd[0].revents = 0;
		ready = poll_retry(pfd, 1, tcp_read_time_out);
		if(ready != 1 || !(pfd[0].revents&POLLIN) || 1 != read(fd,&buff[i],1))
			return -1;
	}
	return (int) size;
}

static int timed_connect(int sock, const struct sockaddr *addr, socklen_t len)
{
	int ret, value;
	socklen_t value_len;
 	struct pollfd pfd[1];

	pfd[0].fd=sock;
	pfd[0].events=POLLOUT;	
	fcntl(sock, F_SETFL, O_NONBLOCK);
  	ret = true_connect(sock, addr,  len);
#ifdef DEBUG
	if(ret == -1) perror("true_connect");
	printf("\nconnect ret=%d\n",ret);
	
	fflush(stdout);
#endif
  	if(ret==-1 && errno==EINPROGRESS) {
		ret=poll_retry(pfd,1,tcp_connect_time_out);
#ifdef DEBUG
		printf("\npoll ret=%d\n",ret);fflush(stdout);
#endif
	      	if(ret == 1) {
			value_len=sizeof(socklen_t);
			getsockopt(sock,SOL_SOCKET,SO_ERROR,&value,&value_len) ;
#ifdef DEBUG
			printf("\nvalue=%d\n",value);fflush(stdout);
#endif
        	       	if(!value)
				ret=0;
			else
				ret=-1;
		} else {
        		      	ret=-1;
		}
	} else {
		if (ret != 0)
			ret=-1;
	} 	

	fcntl(sock, F_SETFL, !O_NONBLOCK);
	return ret;
}


#define INVALID_INDEX 0xFFFFFFFFU
static int tunnel_to(int sock, ip_type ip, unsigned short port, proxy_type pt,char *user,char *pass)
{
#ifdef DEBUG
	PDEBUG("tunnel_to()\n");
#endif	
	char* dns_name = NULL;
	size_t dns_len = 0;
	
	// we use ip addresses with 224.* to lookup their dns name in our table, to allow remote DNS resolution
	// the range 224-255.* is reserved, and it won't go outside (unless the app does some other stuff with
	// the results returned from gethostbyname et al.)
	if(ip.octet[0] == 224) {
		dns_name = string_from_internal_ip(ip);
		if(!dns_name) goto err;
		dns_len = strlen(dns_name);
		if(!dns_len) goto err;
	}
	
	size_t ulen = strlen(user);
	size_t passlen = strlen(pass);
	
	if(ulen > 0xFF || passlen > 0xFF || dns_len > 0xFF) {
		proxychains_write_log(LOG_PREFIX "error: maximum size of 255 for user/pass or domain name!\n");
		goto err;
	}
	
        int len;
        unsigned char buff[BUFF_SIZE];
        //memset (buff, 0, sizeof(buff));
	
	switch(pt) {
		case HTTP_TYPE: {
			if(!dns_len)
				dns_name = inet_ntoa( * (struct in_addr *) &ip.as_int);
			
			snprintf((char*)buff, sizeof(buff), "CONNECT %s:%d HTTP/1.0\r\n", dns_name, ntohs(port));
			
			if (user[0])
			{
				#define HTTP_AUTH_MAX ((0xFF * 2) + 1 + 1)
				// 2 * 0xff: username and pass, plus 1 for ':' and 1 for zero terminator.
				char src[HTTP_AUTH_MAX];
				char dst[(4 * HTTP_AUTH_MAX)];
				
				memcpy(src, user, ulen);
				memcpy(src + ulen, ":", 1);
				memcpy(src + ulen + 1, pass, passlen);
				src[ulen + 1 + passlen] = 0;
				
				encode_base_64(src, dst, sizeof(dst));
				strcat((char*)buff,"Proxy-Authorization: Basic ");
				strcat((char*)buff, dst);
				strcat((char*)buff, "\r\n\r\n");
			}
			else
				strcat((char*)buff, "\r\n");
		
			len = strlen((char*)buff);

			if(len != send(sock, buff, len, 0))
				goto err;
		
			len = 0 ;
			// read header byte by byte.
			while(len < BUFF_SIZE) {
				if(1 == read_n_bytes(sock, (char*) (buff + len), 1))
					len++;
				else
					goto err;
				if (len > 4 &&
					buff[len-1]=='\n'  &&
					buff[len-2]=='\r'  &&
					buff[len-3]=='\n'  &&
					buff[len-4]=='\r'  )
					break;
			}

			// if not ok (200) or response greather than BUFF_SIZE return BLOCKED;
			if (len == BUFF_SIZE ||
				!( buff[9] =='2' &&
				buff[10]=='0' &&
				buff[11]=='0' ))
				return BLOCKED;

			return SUCCESS;
           	}
            	break;
		
		case SOCKS4_TYPE: {
                 		buff[0] = 4; // socks version
  				buff[1] = 1; // connect command
				memcpy(&buff[2],&port,2); // dest port
				if(dns_len) {
					ip.octet[0] = 0;
					ip.octet[1] = 0;
					ip.octet[2] = 0;
					ip.octet[3] = 1;
				}
				memcpy(&buff[4], &ip, 4); // dest host
				len = ulen + 1; // username
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
				
				if((len + 8) != write_n_bytes(sock, (char*) buff, (8+len)))
					goto err;

 				if(8 != read_n_bytes(sock, (char*)buff, 8))
					goto err;
            	
				if (buff[0] != 0 || buff[1] != 90)
					return BLOCKED;

				return SUCCESS;
		}
                break;
		case SOCKS5_TYPE: {
			if(user) {
                 		buff[0]=5;   //version
				buff[1]=2;	//nomber of methods
				buff[2]=0;   // no auth method
	    			buff[3]=2;  /// auth method -> username / password
				if(4!=write_n_bytes(sock, (char*)buff, 4))
					goto err;
       			}
            		else {
            			buff[0]=5;   //version
				buff[1]=1;	//nomber of methods
				buff[2]=0;   // no auth method
				if(3 != write_n_bytes(sock, (char*) buff, 3))
					goto err;
       			}

			if(2 != read_n_bytes(sock, (char*) buff, 2))
		 		goto err;
			
      			if (buff[0] != 5 || (buff[1] != 0 && buff[1] != 2)) {
        			if(buff[0] == 5 && buff[1] == 0xFF)
             				return BLOCKED;
				else
					goto err;
          		}
          			
          		if (buff[1] == 2) {
				// authentication
				char in[2];
				char out[515]; char* cur=out;
				int c;
				*cur++=1; // version
				c = ulen & 0xFF;
				*cur++ = c;
				memcpy(cur, user, c);
				cur += c;
				c = passlen & 0xFF;
				*cur++ = c;
				memcpy(cur, pass, c);
				cur += c;
				
				if((cur-out) != write_n_bytes(sock, out, cur-out))
					goto err;
				
				
				if(2 != read_n_bytes(sock,in,2))
			 		goto err;
				if(in[0] != 1 || in[1] != 0) {
					if(in[0] != 1)
						goto err;
					else
						return BLOCKED;
					}
			}
			int buff_iter = 0;
			buff[buff_iter++] = 5;       // version
			buff[buff_iter++] = 1;       // connect
			buff[buff_iter++] = 0;       // reserved
			
			if(!dns_len) {
				buff[buff_iter++] = 1;       // ip v4
				memcpy(buff + buff_iter, &ip, 4); // dest host
				buff_iter += 4;
			} else {
				buff[buff_iter++] = 3; //dns
				buff[buff_iter++] = dns_len & 0xFF;
				memcpy(buff + buff_iter, dns_name, dns_len);
				buff_iter += dns_len;
			}
			
			memcpy(buff + buff_iter, &port, 2); // dest port
			buff_iter += 2;
			

			if(buff_iter != write_n_bytes(sock, (char*)buff, buff_iter))
				goto err;
	
			if(4 != read_n_bytes(sock, (char*)buff, 4))
				goto err;

			if (buff[0] != 5 || buff[1] != 0)
				goto err;

			switch (buff[3]) {
				
				case 1: len = 4;  break;
				case 4: len = 16; break;
				case 3: len = 0;
					if(1 != read_n_bytes(sock, (char*) &len, 1))
						goto err;
					break;
				default:
					goto err;
			}

			if(len + 2 != read_n_bytes(sock, (char*) buff, len+2))
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

static int start_chain(int *fd, proxy_data *pd, char* begin_mark)
{
	struct sockaddr_in addr;
	
	*fd=socket(PF_INET,SOCK_STREAM,0);
	if(*fd==-1)
		goto error;
	
	proxychains_write_log(LOG_PREFIX "%s "TP" %s:%d ",
				begin_mark,
				inet_ntoa(*(struct in_addr*)&pd->ip),
				htons(pd->port));
	pd->ps=PLAY_STATE;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = (in_addr_t) pd->ip.as_int;
	addr.sin_port = pd->port;
	if (timed_connect (*fd ,(struct sockaddr*)&addr,sizeof(addr))) {
		pd->ps=DOWN_STATE;
		goto error1;
	}
	pd->ps=BUSY_STATE;
	return SUCCESS;
error1:
	proxychains_write_log(TP" timeout\n");
error:
	if(*fd!=-1)
		close(*fd);
	return SOCKET_ERROR;
}

static proxy_data * select_proxy(select_type how, 
		proxy_data *pd, unsigned int proxy_count, unsigned int *offset)
{
	unsigned int i=0, k=0;
	if(*offset >= proxy_count)
		return NULL;
	switch(how) {
		case RANDOMLY:
			srand(time(NULL));
			do {
				k++;
				i = 0 + (unsigned int) (proxy_count * 1.0 * rand()/
						(RAND_MAX + 1.0));
			} while (pd[i].ps != PLAY_STATE && k < proxy_count*100 );
		break;
		case FIFOLY:
			for(i=*offset; i<proxy_count; i++) {
				if(pd[i].ps == PLAY_STATE) {
					*offset = i;
					break;
				}
			}
		default:
		break;
	}
	if (i >= proxy_count)
		i = 0;
	return (pd[i].ps == PLAY_STATE)? &pd[i] : NULL;
}


static void release_all(proxy_data *pd, unsigned int proxy_count)
{
	unsigned int i;
	for(i=0; i<proxy_count; i++)
		pd[i].ps = PLAY_STATE;
	return;
}

static void release_busy(proxy_data *pd, unsigned int proxy_count)
{
	unsigned int i;
	for(i=0; i<proxy_count; i++)
		if(pd[i].ps == BUSY_STATE)
			pd[i].ps = PLAY_STATE;
	return;
}

static unsigned int calc_alive(proxy_data *pd, unsigned int proxy_count)
{
	unsigned int i;
	int alive_count=0;
	release_busy(pd, proxy_count);
	for(i=0; i<proxy_count; i++)
		if(pd[i].ps == PLAY_STATE)
			alive_count++;
	return alive_count;
}


static int chain_step(int ns, proxy_data *pfrom, proxy_data *pto)
{
	int retcode=-1;
	char* hostname;
#ifdef DEBUG
	PDEBUG("chain_step()\n");
#endif
	if(pto->ip.octet[0] == 224) {
		hostname = string_from_internal_ip(pto->ip);
		if(!hostname) goto usenumericip;
	} else {
		usenumericip:
		hostname = inet_ntoa(*(struct in_addr*)&pto->ip);
	}
	
	proxychains_write_log(TP" %s:%d ",  
			hostname,
			htons(pto->port));
	retcode = 
		tunnel_to(ns, pto->ip, pto->port, pfrom->pt, pfrom->user, 
				pfrom->pass);
	switch(retcode) {
		case SUCCESS:
			pto->ps=BUSY_STATE;
			break;
		case BLOCKED:
			pto->ps=BLOCKED_STATE;
			proxychains_write_log("<--denied\n");
			close(ns);
			break;
		case SOCKET_ERROR:
			pto->ps=DOWN_STATE;
			proxychains_write_log("<--timeout\n");
			close(ns);
			break;
	}
	return retcode;
}

int connect_proxy_chain( int sock, ip_type target_ip, 
		unsigned short target_port, proxy_data *pd, 
		unsigned int proxy_count, chain_type ct, unsigned int max_chain )
{
	proxy_data p4;
	proxy_data *p1,*p2,*p3;
	int ns=-1;
	unsigned int offset=0;
	unsigned int alive_count=0;
	unsigned int curr_len=0;
	
	p3=&p4;
#ifdef DEBUG
	PDEBUG("connect_proxy_chain\n");
#endif
	
again:

	switch(ct)  {
		case DYNAMIC_TYPE:
		alive_count = calc_alive(pd,proxy_count);
		offset = 0;
		do {
			if(!(p1=select_proxy(FIFOLY,pd,proxy_count,&offset)))
				goto error_more;
		} while(SUCCESS!=start_chain(&ns,p1,DT) && offset < proxy_count);
		for(;;) {
			p2=select_proxy(FIFOLY,pd,proxy_count,&offset);
			if(!p2)
				break;
			if(SUCCESS!=chain_step(ns,p1,p2)) {
				#ifdef DEBUG
				PDEBUG("GOTO AGAIN 1\n");
				#endif
				goto again;
			}
			p1=p2;
		}
		//proxychains_write_log(TP);
		p3->ip = target_ip;
		p3->port = target_port;
		if(SUCCESS != chain_step(ns, p1, p3))
			goto error;
		break;

	case STRICT_TYPE:
		alive_count = calc_alive(pd, proxy_count);
		offset = 0;
		if(!(p1=select_proxy(FIFOLY, pd, proxy_count, &offset))) {
			#ifdef DEBUG
			PDEBUG("select_proxy failed\n");
			#endif
			goto error_strict;
		}
		if(SUCCESS!=start_chain(&ns, p1, ST)) {
			#ifdef DEBUG
			PDEBUG("start_chain failed\n");
			#endif
			goto error_strict;
		}
		while(offset < proxy_count) {
			if(!(p2 = select_proxy(FIFOLY, pd, proxy_count, &offset)))
				break;
			if(SUCCESS!=chain_step(ns, p1, p2)) {
				#ifdef DEBUG
				PDEBUG("chain_step failed\n");
				#endif
				goto error_strict;
			}
			p1 = p2;
		}
		//proxychains_write_log(TP);
		p3->ip = target_ip;
		p3->port = target_port;
		if(SUCCESS!=chain_step(ns, p1, p3))
			goto error;
		break;
		
	case RANDOM_TYPE:
		alive_count=calc_alive(pd,proxy_count);
		if(alive_count<max_chain)
			goto error_more;
		curr_len=offset=0;
		do {
			if(!(p1=select_proxy(RANDOMLY,pd,proxy_count,&offset)))
				goto error_more;
		} while(SUCCESS!=start_chain(&ns,p1,RT) && offset<max_chain);
		while(++curr_len<max_chain) {
			if(!(p2=select_proxy(RANDOMLY,pd,proxy_count,&offset)))
				goto error_more;
			if(SUCCESS!=chain_step(ns, p1, p2)) {
				#ifdef DEBUG
				PDEBUG("GOTO AGAIN 2\n");
				#endif
				goto again;
			}	
			p1 = p2;
		}
		//proxychains_write_log(TP);
		p3->ip = target_ip;
		p3->port = target_port;
		if(SUCCESS!=chain_step(ns,p1,p3))
			goto error;
			
	}

	proxychains_write_log(TP" OK\n");
	dup2(ns,sock);
	close(ns);
	return 0;
error:
	if(ns!=-1)
		close(ns);
	errno = ECONNREFUSED;  // for nmap ;)
	return -1;
	
error_more:
	proxychains_write_log("\n!!!need more proxies!!!\n");
error_strict:
	#ifdef DEBUG
	PDEBUG("error\n");
	#endif
	release_all(pd,proxy_count);
	if(ns!=-1)
		close(ns);
	errno = ETIMEDOUT;
	return -1;
}

// TODO: all those buffers aren't threadsafe, but since no memory allocation happens there shouldnt be any segfaults
static struct hostent hostent_space;
static in_addr_t resolved_addr;
static char* resolved_addr_p[2];
static char addr_name[1024*8];
static const ip_type local_host = {{127, 0, 0, 1}};
struct hostent* proxy_gethostbyname(const char *name)
{
	char buff[256];
	uint32_t i, hash;
	// yep, new_mem never gets freed. once you passed a fake ip to the client, you can't "retreat" it
	void* new_mem;
	size_t l;

	struct hostent* hp;
	
	resolved_addr_p[0] = (char*) &resolved_addr;
	resolved_addr_p[1] = NULL;
	
	hostent_space.h_addr_list = resolved_addr_p;

	resolved_addr = 0;
	
	gethostname(buff,sizeof(buff));
	
	if(!strcmp(buff, name)) {
		resolved_addr = inet_addr(buff);
		if (resolved_addr == (in_addr_t) (-1))
			resolved_addr = (in_addr_t) (local_host.as_int);
		return &hostent_space;
	}
	
	memset(buff, 0, sizeof(buff));
	
	while ((hp=gethostent()))
		if (!strcmp(hp->h_name,name)) 
			return hp; 
	
	
	hash = dalias_hash((char*) name);
	
#ifdef THREAD_SAFE
	pthread_mutex_lock(&internal_ips_lock);
#endif
	
	// see if we already have this dns entry saved.
	if(internal_ips.counter) {
		for( i = 0; i < internal_ips.counter; i++) {
			if(internal_ips.list[i]->hash == hash && !strcmp(name, internal_ips.list[i]->string)) {
				resolved_addr = make_internal_ip(i);
				PDEBUG("got cached ip for %s\n", name);
				goto have_ip;
			}
		}
	}
	
	// grow list if needed.
	if(internal_ips.capa < internal_ips.counter + 1) {
		PDEBUG("realloc\n");
		new_mem = realloc(internal_ips.list, (internal_ips.capa + 16) * sizeof(void*));
		if(new_mem) {
			internal_ips.capa += 16;
			internal_ips.list = new_mem;
		} else {
			oom:
			proxychains_write_log("out of mem\n");
			goto err_plus_unlock;
		}
	}
	
	resolved_addr = make_internal_ip(internal_ips.counter);
	if(resolved_addr == (in_addr_t) -1) goto err_plus_unlock;

	l = strlen(name);
	new_mem = malloc(sizeof(string_hash_tuple) + l + 1);
	if(!new_mem) 
		goto oom;
	
	PDEBUG("creating new entry %d for ip of %s\n", (int) internal_ips.counter, name);
	
	internal_ips.list[internal_ips.counter] = new_mem;
	internal_ips.list[internal_ips.counter]->hash = hash;
	internal_ips.list[internal_ips.counter]->string = (char*) new_mem + sizeof(string_hash_tuple);
	
	memcpy(internal_ips.list[internal_ips.counter]->string, name, l + 1);
	
	internal_ips.counter += 1;
	
	have_ip:
	
#ifdef THREAD_SAFE
	pthread_mutex_unlock(&internal_ips_lock);
#endif

	
	strncpy(addr_name, name, sizeof(addr_name));
	
	hostent_space.h_name = addr_name;
	hostent_space.h_length = sizeof (in_addr_t);
	return &hostent_space;

err_plus_unlock:
#ifdef THREAD_SAFE
	pthread_mutex_unlock(&internal_ips_lock);
#endif
	return NULL;
}
int proxy_getaddrinfo(const char *node, const char *service,
		const struct addrinfo *hints,
		struct addrinfo **res)
{
	struct servent *se = NULL;
	struct hostent *hp = NULL;
	struct sockaddr* sockaddr_space = NULL;
	struct addrinfo*  addrinfo_space = NULL;
	
//	printf("proxy_getaddrinfo node %s service %s\n",node,service);
	addrinfo_space = malloc(sizeof(struct addrinfo));
	if(!addrinfo_space)
		goto err1;
	sockaddr_space = malloc(sizeof(struct sockaddr));
	if(!sockaddr_space)
		goto err2;
	memset(sockaddr_space, 0, sizeof(*sockaddr_space));
	memset(addrinfo_space, 0, sizeof(*addrinfo_space));
	if (node &&
	    !inet_aton(node,&((struct sockaddr_in*)sockaddr_space)->sin_addr)) {
		hp = proxy_gethostbyname(node);
		if (hp) 
			memcpy(&((struct sockaddr_in*)sockaddr_space)->sin_addr,
				*(hp->h_addr_list),
				sizeof(in_addr_t));
		else
			goto err3;
	}
	if (service)
		se = getservbyname(service, NULL);
	
	if (!se) {
		((struct sockaddr_in*)sockaddr_space)->sin_port = 
			htons(atoi(service?:"0"));
	} else 
		((struct sockaddr_in*)sockaddr_space)->sin_port = se->s_port;

	*res = addrinfo_space;
	(*res)->ai_addr = sockaddr_space;
	if (node)
		strcpy(addr_name, node);
	(*res)->ai_canonname = addr_name;
	(*res)->ai_next = NULL;
	(*res)->ai_family = sockaddr_space->sa_family = AF_INET;
	(*res)->ai_socktype = hints->ai_socktype;
	(*res)->ai_flags = hints->ai_flags;
	(*res)->ai_protocol = hints->ai_protocol;
	(*res)->ai_addrlen = sizeof(*sockaddr_space);
	goto out;
err3:
	free(sockaddr_space);
err2:
	free(addrinfo_space);
err1:
	return 1;
out:
	return 0;
}
