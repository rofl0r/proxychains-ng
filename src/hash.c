#include "hash.h"

/* dalias' version of the elf hash */
uint32_t dalias_hash(char *s0) {
	unsigned char *s = (void *) s0;
	uint_fast32_t h = 0;
	while(*s) {
		h = 16 * h + *s++;
		h ^= h >> 24 & 0xf0;
	}
	return h & 0xfffffff;
}
