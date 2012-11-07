#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/select.h>
#include <assert.h>
#include "shm.h"
#include "debug.h"

enum at_msgtype {
	ATM_REALLOC,
	ATM_STRINGDUMP,
	ATM_EXIT,
};

static pthread_t allocator_thread;
static pthread_attr_t allocator_thread_attr;
static int req_pipefd[2];
static int resp_pipefd[2];
static size_t *at_oldsize;
static size_t *at_newsize;
static void **at_data;
struct stringpool mem;

static void* threadfunc(void* x) {
	(void) x;
	int readfd = req_pipefd[0];
	int writefd = resp_pipefd[1];
	fd_set fds;
	FD_ZERO(&fds);
	FD_SET(readfd, &fds);
	int ret;
	int msg;
	while((ret = select(readfd+1, &fds, NULL, NULL, NULL)) != -1) {
		assert(ret);
		if(read(readfd, &msg, sizeof(int)) != sizeof(int)) {
			perror("read");
		} else {
			void *nu;
			switch(msg) {
				case ATM_REALLOC:
					nu = shm_realloc(*at_data, *at_oldsize, *at_newsize);
					break;
				case ATM_STRINGDUMP:
					nu = stringpool_add(&mem, *at_data, *at_newsize);
					break;
				case ATM_EXIT:
					return 0;
				default:
					abort();
			}
			*at_data = nu;
			write(writefd, &msg, sizeof(int)); 
		}
	}
	return 0;
}

static void initpipe(int* fds) {
	if(pipe2(fds, 0/*O_CLOEXEC*/) == -1) {
		perror("pipe");
		exit(1);
	}
}

/* initialize with pointers to shared memory. these will
 * be used to place responses and arguments */
void at_init(void **data, size_t *oldsize, size_t *newsize) {
	PFUNC();
	initpipe(req_pipefd);
	initpipe(resp_pipefd);
	at_oldsize = oldsize;
	at_newsize = newsize;
	at_data = data;
	stringpool_init(&mem);
	pthread_attr_init(&allocator_thread_attr);
	pthread_attr_setstacksize(&allocator_thread_attr, 16 * 1024);
	pthread_create(&allocator_thread, &allocator_thread_attr, threadfunc, 0);
}

void at_close(void) {
	PFUNC();
	const int msg = ATM_EXIT;
	write(req_pipefd[1], &msg, sizeof(int));
	pthread_join(allocator_thread, NULL);
	close(req_pipefd[0]);
	close(req_pipefd[1]);
	close(resp_pipefd[0]);
	close(resp_pipefd[1]);
}

static int wait_reply(void) {
	PFUNC();
	int readfd = resp_pipefd[0];
	fd_set fds;
	FD_ZERO(&fds);
	FD_SET(readfd, &fds);
	int ret;
	while((ret = select(readfd+1, &fds, NULL, NULL, NULL)) <= 0) {
		if(ret < 0) perror("select2");
	}
	read(readfd, &ret, sizeof(int));
	return ret;
}

void *at_realloc(void* old, size_t oldsize, size_t newsize) {
	PFUNC();
	*at_data = old;
	*at_oldsize = oldsize;
	*at_newsize = newsize;
	const int msg = ATM_REALLOC;
	write(req_pipefd[1], &msg, sizeof(int));
	assert(wait_reply() == msg);
	return *at_data;
}

char *at_dumpstring(char* s, size_t len) {
	PFUNC();
	*at_data = s;
	*at_newsize = len;
	const int msg = ATM_STRINGDUMP;
	write(req_pipefd[1], &msg, sizeof(int));
	assert(wait_reply() == msg);
	return *at_data;
}
