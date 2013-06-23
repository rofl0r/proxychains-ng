#ifndef DEBUG_H
#define DEBUG_H

#ifdef DEBUG
# include <stdio.h>
# define PSTDERR(fmt, args...) do { dprintf(2,fmt, ## args); } while(0)
# define PDEBUG(fmt, args...) PSTDERR("DEBUG:"fmt, ## args)

# include "core.h"
void DUMP_PROXY_DATA_LIST(proxy_data *plist, unsigned int count);
void DUMP_PROXY_CHAIN(proxy_chain *pchain);

#else
# define PDEBUG(fmt, args...) do {} while (0)
# define DUMP_PROXY_CHAIN(args...) do {} while (0)
# define DUMP_PROXY_DATA_LIST(args...) do {} while (0)
#endif

# define PFUNC() do { PDEBUG("pid[%d]:%s\n", getpid(), __FUNCTION__); } while(0)

#endif

