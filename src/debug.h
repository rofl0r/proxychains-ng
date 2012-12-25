#ifndef DEBUG_H
#define DEBUG_H

#ifdef DEBUG
# include <stdio.h>
# define PDEBUG(fmt, args...) do { dprintf(2,"DEBUG:"fmt, ## args); } while(0)
#else
# define PDEBUG(fmt, args...) do {} while (0)
#endif

# define PFUNC() do { PDEBUG("pid[%d]:%s\n", getpid(), __FUNCTION__); } while(0)

#endif

