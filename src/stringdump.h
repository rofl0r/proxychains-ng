#ifndef STRINGDUMP_H
#define STRINGDUMP_H

#include "shm.h"
#include <unistd.h>

char *dumpstring(char* s, size_t len);
void dumpstring_init(void);

//RcB: DEP "stringdump.h"

#endif
