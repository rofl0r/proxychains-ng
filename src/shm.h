#ifndef SHM_H
#define SHM_H
#include <unistd.h>

struct stringpool {
	size_t alloced;
	size_t used;
	char* start;
};

void stringpool_init(struct stringpool* sp);
char* stringpool_add(struct stringpool *sp, char* s, size_t len);
#if 0
void *shm_realloc(void* old, size_t old_size, size_t new_size);
#endif
//RcB: DEP "shm.c"
#endif
