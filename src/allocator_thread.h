#include <unistd.h>

void *at_realloc(void* old, size_t oldsize, size_t newsize);
char *at_dumpstring(char* s, size_t len);
void at_init(void **data, size_t *oldsize, size_t *newsize);
void at_close(void);

//RcB: DEP "allocator_thread.c"
