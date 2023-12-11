#ifndef DEBUG_H
#define DEBUG_H

# include <stdio.h>

#ifdef DEBUG
# define PSTDERR(fmt, args...) do { dprintf(2,fmt, ## args); } while(0)
# define PDEBUG(fmt, args...) PSTDERR("DEBUG:pid[%d]:" fmt, getpid(), ## args)
# define DEBUGDECL(args...) args
# define DUMP_PROXY_CHAIN(A, B) dump_proxy_chain(A, B)
# define DUMP_BUFFER(data, len) dump_buffer(data, len)
# define DUMP_RELAY_CHAINS_LIST(list) dump_relay_chains_list(list)
#else
# define PDEBUG(fmt, args...) do {} while (0)
# define DEBUGDECL(args...)
# define DUMP_PROXY_CHAIN(args...) do {} while (0)
# define DUMP_BUFFER(data, len) do {} while (0)
# define DUMP_RELAY_CHAINS_LIST(list) do {} while (0)
#endif

# define PFUNC() do { PDEBUG("%s()\n", __FUNCTION__); } while(0)

#include "core.h"
void dump_proxy_chain(proxy_data *pchain, unsigned int count);
void dump_buffer(unsigned char* data, size_t len);
void dump_relay_chain(udp_relay_chain* chain);
void dump_relay_chains_list(udp_relay_chain_list list);

#endif

