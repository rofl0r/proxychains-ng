#include "sblist.h"
#include <string.h>

void sblist_delete(sblist* l, size_t item) {
	if (l->count && item < l->count) {
		memmove(sblist_item_from_index(l, item), sblist_item_from_index(l, item + 1), (sblist_getsize(l) - (item + 1)) * l->itemsize);
		l->count--;
	}
}
