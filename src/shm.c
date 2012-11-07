#include <sys/mman.h>
#include <assert.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <limits.h>
#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif
#include "shm.h"
#include "debug.h"

/* allocates shared memory which can be accessed from the parent and its childs */
void *shm_realloc(void* old, size_t old_size, size_t new_size) {
	//PFUNC();
	void *nu = mmap(NULL, new_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0);
	if(old) {
		if(!nu) return NULL;
		assert(new_size >= old_size);
		memcpy(nu, old, old_size);
		munmap(old, old_size);
	}
	return nu;
}

void stringpool_init(struct stringpool* sp) {
	PFUNC();
	memset(sp, 0, sizeof *sp);
}

char* stringpool_add(struct stringpool *sp, char* s, size_t len) {
	//PFUNC();
	if(len > sp->alloced - sp->used) {
		size_t newsz = sp->used + len;
		size_t inc = PAGE_SIZE - (newsz % PAGE_SIZE);
		newsz += (inc == PAGE_SIZE) ? 0 : inc;
		void* p = shm_realloc(sp->start, sp->alloced, newsz);
		if(p) {
			sp->start = p;
			sp->alloced = newsz;
		} else 
			return 0;
	}
	char* ret = sp->start + sp->used;
	memcpy(ret, s, len);
	sp->used += len;
	return ret;
}
