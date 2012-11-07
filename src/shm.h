#include <unistd.h>

struct stringpool {
	size_t alloced;
	size_t used;
	char* start;
};

void stringpool_init(struct stringpool* sp);
char* stringpool_add(struct stringpool *sp, char* s, size_t len);

void *shm_realloc(void* old, size_t old_size, size_t new_size);

//RcB: DEP "shm.c"
