#ifndef SBLIST_H
#define SBLIST_H

/* this file is part of libulz, as of commit 8ab361a27743aaf025323ee43b8b8876dc054fdd
   modified for direct inclusion in microsocks. */


#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
/*
 * simple buffer list.
 * 
 * this thing here is basically a generic dynamic array
 * will realloc after every blockitems inserts
 * can store items of any size.
 * 
 * so think of it as a by-value list, as opposed to a typical by-ref list.
 * you typically use it by having some struct on the stack, and pass a pointer
 * to sblist_add, which will copy the contents into its internal memory.
 * 
 */

typedef struct {
	size_t itemsize;
	size_t blockitems;
	size_t count;
	size_t capa;
	char* items;
} sblist;

#define sblist_getsize(X) ((X)->count)
#define sblist_get_count(X) ((X)->count)
#define sblist_empty(X) ((X)->count == 0)

// for dynamic style
sblist* sblist_new(size_t itemsize, size_t blockitems);
void sblist_free(sblist* l);

//for static style
void sblist_init(sblist* l, size_t itemsize, size_t blockitems);
void sblist_free_items(sblist* l);

// accessors
void* sblist_get(sblist* l, size_t item);
// returns 1 on success, 0 on OOM
int sblist_add(sblist* l, void* item);
int sblist_set(sblist* l, void* item, size_t pos);
void sblist_delete(sblist* l, size_t item);
char* sblist_item_from_index(sblist* l, size_t idx);
int sblist_grow_if_needed(sblist* l);
int sblist_insert(sblist* l, void* item, size_t pos);
/* same as sblist_add, but returns list index of new item, or -1 */
size_t sblist_addi(sblist* l, void* item);
void sblist_sort(sblist *l, int (*compar)(const void *, const void *));
/* insert element into presorted list, returns listindex of new entry or -1*/
size_t sblist_insert_sorted(sblist* l, void* o, int (*compar)(const void *, const void *));

#ifndef __COUNTER__
#define __COUNTER__ __LINE__
#endif

#define __sblist_concat_impl( x, y ) x##y
#define __sblist_macro_concat( x, y ) __sblist_concat_impl( x, y )
#define __sblist_iterator_name __sblist_macro_concat(sblist_iterator, __COUNTER__)

// use with custom iterator variable
#define sblist_iter_counter(LIST, ITER, PTR) \
	for(size_t ITER = 0; (PTR = sblist_get(LIST, ITER)), ITER < sblist_getsize(LIST); ITER++)

// use with custom iterator variable, which is predeclared
#define sblist_iter_counter2(LIST, ITER, PTR) \
	for(ITER = 0; (PTR = sblist_get(LIST, ITER)), ITER < sblist_getsize(LIST); ITER++)

// use with custom iterator variable, which is predeclared and signed
// useful for a loop which can delete items from the list, and then decrease the iterator var.
#define sblist_iter_counter2s(LIST, ITER, PTR) \
	for(ITER = 0; (PTR = sblist_get(LIST, ITER)), ITER < (ssize_t) sblist_getsize(LIST); ITER++)


// uses "magic" iterator variable
#define sblist_iter(LIST, PTR) sblist_iter_counter(LIST, __sblist_iterator_name, PTR)

#ifdef __cplusplus
}
#endif

#pragma RcB2 DEP "sblist.c" "sblist_delete.c"

#endif
