#include "stringdump.h"
#include "debug.h"

struct stringpool mem;

char *dumpstring(char* s, size_t len) {
	PFUNC();
	return stringpool_add(&mem, s, len);
}

void dumpstring_init(void) {
	stringpool_init(&mem);
}
