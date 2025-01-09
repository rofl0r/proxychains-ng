#undef _GNU_SOURCE
#define _GNU_SOURCE
#undef _POSIX_C_SOURCE
#define _DARWIN_C_SOURCE
#include <limits.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/select.h>
#include <assert.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <errno.h>
#include <sys/mman.h>
#include "allocator_thread.h"
#include "debug.h"
#include "ip_type.h"
#include "mutex.h"
#include "hash.h"
#include "remotedns.h"

/* stuff for our internal translation table */

typedef struct {
	uint32_t hash;
	char* string;
} string_hash_tuple;

typedef struct {
	uint32_t counter;
	uint32_t capa;
	string_hash_tuple** list;
} internal_ip_lookup_table;

static void *dumpstring(char* s, size_t len) {
	char* p = malloc(len);
	if(p) memcpy(p, s, len);
	return p;
}

static pthread_mutex_t *internal_ips_lock;
static internal_ip_lookup_table *internal_ips;

uint32_t index_from_internal_ip(ip_type4 internalip) {
	PFUNC();
	ip_type4 tmp = internalip;
	uint32_t ret;
	ret = tmp.octet[3] + (tmp.octet[2] << 8) + (tmp.octet[1] << 16);
	ret -= 1;
	return ret;
}

char *string_from_internal_ip(ip_type4 internalip) {
	PFUNC();
	char *res = NULL;
	uint32_t index = index_from_internal_ip(internalip);
	if(index < internal_ips->counter)
		res = internal_ips->list[index]->string;
	return res;
}

extern unsigned int remote_dns_subnet;
ip_type4 make_internal_ip(uint32_t index) {
	ip_type4 ret;
	index++; // so we can start at .0.0.1
	if(index > 0xFFFFFF)
		return IPT4_INVALID;
	ret.octet[0] = remote_dns_subnet & 0xFF;
	ret.octet[1] = (index & 0xFF0000) >> 16;
	ret.octet[2] = (index & 0xFF00) >> 8;
	ret.octet[3] = index & 0xFF;
	return ret;
}

static ip_type4 ip_from_internal_list(char* name, size_t len) {
	uint32_t hash = dalias_hash((char *) name);
	size_t i;
	ip_type4 res;
	void* new_mem;
	// see if we already have this dns entry saved.
	if(internal_ips->counter) {
		for(i = 0; i < internal_ips->counter; i++) {
			if(internal_ips->list[i]->hash == hash && !strcmp(name, internal_ips->list[i]->string)) {
				res = make_internal_ip(i);
				PDEBUG("got cached ip for %s\n", name);
				goto have_ip;
			}
		}
	}
	// grow list if needed.
	if(internal_ips->capa < internal_ips->counter + 1) {
		PDEBUG("realloc\n");
		new_mem = realloc(internal_ips->list, (internal_ips->capa + 16) * sizeof(void *));
		if(new_mem) {
			internal_ips->capa += 16;
			internal_ips->list = new_mem;
		} else {
	oom:
			PDEBUG("out of mem\n");
			goto err_plus_unlock;
		}
	}

	res = make_internal_ip(internal_ips->counter);
	if(res.as_int == IPT4_INVALID.as_int)
		goto err_plus_unlock;

	string_hash_tuple tmp = { 0 };
	new_mem = dumpstring((char*) &tmp, sizeof(string_hash_tuple));
	if(!new_mem)
		goto oom;

	PDEBUG("creating new entry %d for ip of %s\n", (int) internal_ips->counter, name);

	internal_ips->list[internal_ips->counter] = new_mem;
	internal_ips->list[internal_ips->counter]->hash = hash;

	new_mem = dumpstring((char*) name, len);

	if(!new_mem) {
		internal_ips->list[internal_ips->counter] = 0;
		goto oom;
	}
	internal_ips->list[internal_ips->counter]->string = new_mem;

	internal_ips->counter += 1;

	have_ip:

	return res;
	err_plus_unlock:

	PDEBUG("return err\n");
	return IPT4_INVALID;
}

/* stuff for communication with the allocator thread */

enum at_direction {
	ATD_SERVER = 0,
	ATD_CLIENT,
	ATD_MAX,
};

static pthread_t allocator_thread;
int req_pipefd[2];
int resp_pipefd[2];

static int wait_data(int readfd) {
	PFUNC();
	fd_set fds;
	FD_ZERO(&fds);
	FD_SET(readfd, &fds);
	int ret;
	while((ret = select(readfd+1, &fds, NULL, NULL, NULL)) <= 0) {
		if(ret < 0) {
			int e = errno;
			if(e == EINTR) continue;
#ifdef __GLIBC__
			char emsg[1024];
			char* x = strerror_r(errno, emsg, sizeof emsg);
			dprintf(2, "select2: %s\n", x);
#endif
			return 0;
		}
	}
	return 1;
}

static int trywrite(int fd, void* buf, size_t bytes) {
	ssize_t ret;
	unsigned char *out = buf;
again:
	ret = true_write(fd, out, bytes);
	switch(ret) {
		case -1:
			if(errno == EINTR) goto again;
		case  0:
			return 0;
		default:
			if(ret == bytes || !bytes) return 1;
			out += ret;
			bytes -= ret;
			goto again;
	}
}

static int sendmessage(enum at_direction dir, struct at_msg *msg) {
	static int* destfd[ATD_MAX] = { [ATD_SERVER] = &req_pipefd[1], [ATD_CLIENT] = &resp_pipefd[1] };
	assert(msg->h.datalen <= MSG_LEN_MAX);
	int ret = trywrite(*destfd[dir], msg, sizeof (msg->h)+msg->h.datalen);
	assert(msg->h.datalen <= MSG_LEN_MAX);
	return ret;
}

static int tryread(int fd, void* buf, size_t bytes) {
	ssize_t ret;
	unsigned char *out = buf;
again:
	ret = true_read(fd, out, bytes);
	switch(ret) {
		case -1:
			if(errno == EINTR) goto again;
		case  0:
			return 0;
		default:
			if(ret == bytes || !bytes) return 1;
			out += ret;
			bytes -= ret;
			goto again;
	}
}
static int readmsg(int fd, struct at_msg *msg) {
	int ret = tryread(fd, msg, sizeof(msg->h));
	if(ret != 1) return ret;
	return tryread(fd, &msg->m, msg->h.datalen);
}

static int getmessage(enum at_direction dir, struct at_msg *msg) {
	static int* readfd[ATD_MAX] = { [ATD_SERVER] = &req_pipefd[0], [ATD_CLIENT] = &resp_pipefd[0] };
	ssize_t ret;
	if((ret = wait_data(*readfd[dir]))) {
		if(!readmsg(*readfd[dir], msg))
			return 0;
		assert(msg->h.datalen <= MSG_LEN_MAX);
	}
	return ret;
}

static void* threadfunc(void* x) {
	(void) x;
	int ret;
	struct at_msg msg;
	while((ret = getmessage(ATD_SERVER, &msg))) {
		switch(msg.h.msgtype) {
			case ATM_GETIP:
				/* client wants an ip for a DNS name. iterate our list and check if we have an existing entry.
					* if not, create a new one. */
				msg.m.ip = ip_from_internal_list(msg.m.host, msg.h.datalen);
				msg.h.datalen = sizeof(ip_type4);
				break;
			case ATM_GETNAME: {
				char *host = string_from_internal_ip(msg.m.ip);
				if(host) {
					size_t l = strlen(host);
					assert(l+1 < MSG_LEN_MAX);
					memcpy(msg.m.host, host, l + 1);
					msg.h.datalen = l + 1;
				} else {
					msg.h.datalen = 0;
				}
				break;
			}
			case ATM_EXIT:
				return 0;
			default:
				abort();
		}
		ret = sendmessage(ATD_CLIENT, &msg);
	}
	return 0;
}

/* API to access the internal ip mapping */

ip_type4 at_get_ip_for_host(char* host, size_t len) {
	ip_type4 readbuf;
	MUTEX_LOCK(internal_ips_lock);
	if(len > MSG_LEN_MAX) goto inv;
	struct at_msg msg = {.h.msgtype = ATM_GETIP, .h.datalen = len + 1 };
	memcpy(msg.m.host, host, len+1);
	if(sendmessage(ATD_SERVER, &msg) &&
	   getmessage(ATD_CLIENT, &msg)) readbuf = msg.m.ip;
	else {
		inv:
		readbuf = IPT4_INVALID;
	}
	assert(msg.h.msgtype == ATM_GETIP);
	MUTEX_UNLOCK(internal_ips_lock);
	return readbuf;
}

size_t at_get_host_for_ip(ip_type4 ip, char* readbuf) {
	struct at_msg msg = {.h.msgtype = ATM_GETNAME, .h.datalen = sizeof(ip_type4), .m.ip = ip };
	size_t res = 0;
	MUTEX_LOCK(internal_ips_lock);
	if(sendmessage(ATD_SERVER, &msg) && getmessage(ATD_CLIENT, &msg)) {
		if((int16_t) msg.h.datalen <= 0) res = 0;
		else {
			memcpy(readbuf, msg.m.host, msg.h.datalen);
			res = msg.h.datalen - 1;
		}
	}
	assert(msg.h.msgtype == ATM_GETNAME);
	MUTEX_UNLOCK(internal_ips_lock);
	return res;
}


static void initpipe(int* fds) {
	int retval;

#ifdef HAVE_PIPE2
	retval = pipe2(fds, O_CLOEXEC);
#else
	retval = pipe(fds);
	if(retval == 0) {
		fcntl(fds[0], F_SETFD, FD_CLOEXEC);
		fcntl(fds[1], F_SETFD, FD_CLOEXEC);
	}
#endif
	if(retval == -1) {
		perror("pipe");
		exit(1);
	}
}

#ifndef MAX
#define MAX(x, y) ((x) > (y) ? (x) : (y))
#endif

#if !defined(PTHREAD_STACK_MIN) || defined(__APPLE__)
/* MAC says its min is 8KB, but then crashes in our face. thx hunkOLard */
#define PTHREAD_STACK_MIN 64*1024
#endif

/* initialize with pointers to shared memory. these will
 * be used to place responses and arguments */
void at_init(void) {
	PFUNC();
	void *shm = mmap(0, 4096, PROT_WRITE|PROT_READ, MAP_ANON|MAP_SHARED, -1, 0);
	assert(shm);
	internal_ips_lock = shm;
	internal_ips = (void*)((char*)shm + 2048);

	MUTEX_INIT(internal_ips_lock);
	memset(internal_ips, 0, sizeof *internal_ips);
	initpipe(req_pipefd);
	initpipe(resp_pipefd);
	pthread_attr_t allocator_thread_attr;
	pthread_attr_init(&allocator_thread_attr);
	pthread_attr_setstacksize(&allocator_thread_attr, MAX(16 * 1024, PTHREAD_STACK_MIN));
	pthread_create(&allocator_thread, &allocator_thread_attr, threadfunc, 0);
	pthread_attr_destroy(&allocator_thread_attr);
}

void at_close(void) {
	PFUNC();
	const int msg = ATM_EXIT;
	true_write(req_pipefd[1], &msg, sizeof(int));
	pthread_join(allocator_thread, NULL);
	true_close(req_pipefd[0]);
	true_close(req_pipefd[1]);
	true_close(resp_pipefd[0]);
	true_close(resp_pipefd[1]);
	MUTEX_DESTROY(internal_ips_lock);
}
