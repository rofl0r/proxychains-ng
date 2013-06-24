
#ifdef DEBUG
# include "core.h"
# include "common.h"
# include "debug.h"

const char *proxy_type_strmap[] = {
    "http",
    "socks4",
    "socks5",
};

const char *chain_type_strmap[] = {
    "dynamic_chain",
    "strict_chain",
    "random_chain",
    "round_robin_chain",
};

const char *proxy_state_strmap[] = {
    "play",
    "down",
    "blocked",
    "busy",
};

void DUMP_PROXY_CHAIN(proxy_data *pchain, unsigned int count) {
    char ip_buf[16];
    for (; count; pchain++, count--) {
        pc_stringfromipv4(&pchain->ip.octet[0], ip_buf);
        PDEBUG("[%s] %s %s:%d", proxy_state_strmap[pchain->ps],
            proxy_type_strmap[pchain->pt], 
            ip_buf, htons(pchain->port));
        if (*pchain->user || *pchain->pass) {
            PSTDERR(" [u=%s,p=%s]", pchain->user, pchain->pass);
        }
        PSTDERR("\n");
    }
}

#endif
