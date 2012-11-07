#include "../src/shm.h"
#include <assert.h>

#define s(A) (sizeof(A) - 1)
#define ss(A) (A), s(A)

int main() {
	char buf4096[4096];
	struct stringpool sp;
	stringpool_init(&sp);
	char *r;
	size_t pos = 0;
	r = stringpool_add(&sp, ss("AAAAA"));
	assert(r == sp.start);
	
	pos += s("AAAAA");
	assert(sp.alloced == 4096);
	assert(sp.used == pos);
	
	r = stringpool_add(&sp, buf4096, sizeof(buf4096));
	assert(r == sp.start + pos);
	
	pos += sizeof(buf4096);
	assert(sp.alloced == 4096 * 2);
	assert(sp.used == pos);
	
	r = stringpool_add(&sp, buf4096, 4096 - s("AAAAA"));
	assert(r == sp.start + pos);
	pos += 4096 - s("AAAAA");
	assert(pos == 4096 * 2);

	assert(sp.alloced == 4096 * 2);
	assert(sp.used == pos);
	
	
	
	return 0;
	
}