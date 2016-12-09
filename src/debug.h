#ifndef DEBUG_H
#define DEBUG_H

#ifdef DEBUG
# include <stdio.h>
# if defined __STRICT_ANSI__ && \
    (defined __STDC_VERSION__ && __STDC_VERSION__ >= 199901L)
#  define PSTDERR(fmt, ...) do { dprintf(2,fmt, __VA_ARGS__); } while(0)
#  define PDEBUG(fmt, ...) PSTDERR("DEBUG:"fmt, __VA_ARGS__)
#  define DEBUGDECL(...) __VA_ARGS__
# else
#  define PSTDERR(fmt, args...) do { dprintf(2,fmt, ## args); } while(0)
#  define PDEBUG(fmt, args...) PSTDERR("DEBUG:"fmt, ## args)
#  define DEBUGDECL(args...) args
# endif

# include "core.h"
void DUMP_PROXY_CHAIN(proxy_data *pchain, unsigned int count);

#else
# if defined __STRICT_ANSI__ && \
    (defined __STDC_VERSION__ && __STDC_VERSION__ >= 199901L)
#  define PSTDERR(fmt, ...) do {} while (0)
#  define PDEBUG(fmt, ...) do {} while (0)
#  define DEBUGDECL(...)
#  define DUMP_PROXY_CHAIN(...) do {} while (0)
# else
#  define PSTDERR(fmt, args...) do {} while (0)
#  define PDEBUG(fmt, args...) do {} while (0)
#  define DEBUGDECL(args...)
#  define DUMP_PROXY_CHAIN(args...) do {} while (0)
# endif
#endif

#define PSTDERR1(msg) PSTDERR("%s", msg)
#define PDEBUG1(msg) PDEBUG("%s", msg)

#if !defined __STDC_VERSION__ || __STDC_VERSION__ < 199901L
# if defined __GNUC__ && __GNUC__ >= 2
#  define __func__ __FUNCTION__
# else
#  define __func__ "<unknown>"
# endif
#endif

#define PFUNC() do { PDEBUG("pid[%d]:%s\n", getpid(), __func__); } while(0)

#endif

