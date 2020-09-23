#undef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#include "sblist.h"
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#define MY_PAGE_SIZE 4096

sblist* sblist_new(size_t itemsize, size_t blockitems) {
	sblist* ret = (sblist*) malloc(sizeof(sblist));
	sblist_init(ret, itemsize, blockitems);
	return ret;
}

static void sblist_clear(sblist* l) {
	l->items = NULL;
	l->capa = 0;
	l->count = 0;
}

void sblist_init(sblist* l, size_t itemsize, size_t blockitems) {
	if(l) {
		l->blockitems = blockitems ? blockitems : MY_PAGE_SIZE / itemsize;
		l->itemsize = itemsize;
		sblist_clear(l);
	}
}

void sblist_free_items(sblist* l) {
	if(l) {
		if(l->items) free(l->items);
		sblist_clear(l);
	}
}

void sblist_free(sblist* l) {
	if(l) {
		sblist_free_items(l);
		free(l);
	}
}

char* sblist_item_from_index(sblist* l, size_t idx) {
	return l->items + (idx * l->itemsize);
}

void* sblist_get(sblist* l, size_t item) {
	if(item < l->count) return (void*) sblist_item_from_index(l, item);
	return NULL;
}

int sblist_set(sblist* l, void* item, size_t pos) {
	if(pos >= l->count) return 0;
	memcpy(sblist_item_from_index(l, pos), item, l->itemsize);
	return 1;
}

int sblist_grow_if_needed(sblist* l) {
	char* temp;
	if(l->count == l->capa) {
		temp = realloc(l->items, (l->capa + l->blockitems) * l->itemsize);
		if(!temp) return 0;
		l->capa += l->blockitems;
		l->items = temp;
	}
	return 1;
}

int sblist_add(sblist* l, void* item) {
	if(!sblist_grow_if_needed(l)) return 0;
	l->count++;
	return sblist_set(l, item, l->count - 1);
}
