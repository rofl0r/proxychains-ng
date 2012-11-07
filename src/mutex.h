#ifndef MUTEX_H
#define MUTEX_H

#include <pthread.h>
# define MUTEX_LOCK(x) pthread_mutex_lock(x)
# define MUTEX_UNLOCK(x) pthread_mutex_unlock(x)
# define MUTEX_INIT(x) pthread_mutex_init(x, NULL)
# define MUTEX_DESTROY(x) pthread_mutex_destroy(x)

#endif
