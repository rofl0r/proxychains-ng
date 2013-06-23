
#ifdef DEBUG
# include "core.h"
# include "common.h"
# include "debug.h"


void DUMP_PROXY_DATA_LIST(proxy_data *plist, unsigned int count) {
    char ip_buf[16];
    for (; count; plist++, count--) {
        pc_stringfromipv4(&plist->ip.octet[0], ip_buf);
        PDEBUG("PDATA:[%s] %s %s:%d", proxy_state_strmap[plist->ps],
            proxy_type_strmap[plist->pt], 
            ip_buf, htons(plist->port));
        if (*plist->user || *plist->pass) {
            PSTDERR(" [u=%s,p=%s]", plist->user, plist->pass);
        }
        PSTDERR("\n");
    }
}

void DUMP_PROXY_CHAIN(proxy_chain *pchain) {
    PDEBUG("PCHAIN:[name: \"%s\"]\n", pchain->name);
    PDEBUG("PCHAIN:chain type: %s\n", chain_type_strmap[pchain->ct]);
    PDEBUG("PCHAIN:tcp_read_time_out: %d\n", pchain->tcp_read_time_out);
    PDEBUG("PCHAIN:tcp_connect_time_out: %d\n", pchain->tcp_connect_time_out);
    PDEBUG("PCHAIN:max_chain: %d\n", pchain->max_chain);
    PDEBUG("PCHAIN:offset: %d\n", pchain->offset);
    PDEBUG("PCHAIN:count: %d\n", pchain->count);
    DUMP_PROXY_DATA_LIST(pchain->pd, pchain->count);
}

#endif
