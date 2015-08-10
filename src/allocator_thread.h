#ifndef ALLOCATOR_THREAD_H
#define ALLOCATOR_THREAD_H

#include <unistd.h>
#include "ip_type.h"

#define MSG_LEN_MAX 256

extern int req_pipefd[2];
extern int resp_pipefd[2];

void at_init(void);
void at_close(void);
size_t at_get_host_for_ip(ip_type4 ip, char* readbuf);
ip_type4 at_get_ip_for_host(char* host, size_t len);

//RcB: DEP "allocator_thread.c"
#endif

