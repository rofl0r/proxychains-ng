#ifndef HSEARCH_H
#define HSEARCH_H

#include <stdlib.h>

typedef union htab_value {
	void *p;
	size_t n;
} htab_value;

#define HTV_N(N) (htab_value) {.n = N}
#define HTV_P(P) (htab_value) {.p = P}

struct htab * htab_create(size_t);
void htab_destroy(struct htab *);
htab_value* htab_find(struct htab *, char* key);
int htab_insert(struct htab *, char*, htab_value);
int htab_delete(struct htab *htab, char* key);
size_t htab_next(struct htab *, size_t iterator, char** key, htab_value **v);

#endif
