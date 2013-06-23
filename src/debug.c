
#ifdef DEBUG
# include <string.h>
# include "core.h"
# include "common.h"
# include "debug.h"


void DUMP_PROXY_DATA_LIST_PREFIX(proxy_data *plist, unsigned int count, const char* prefix) {
    char ip_buf[16], buff[48] = {'\0'};
    strcat(strcat(buff, prefix), "PDATA:");
    for (; count; plist++, count--) {
        pc_stringfromipv4(&plist->ip.octet[0], ip_buf);
        PDEBUG("%s[%s] %s %s:%d", buff, proxy_state_strmap[plist->ps],
            proxy_type_strmap[plist->pt], 
            ip_buf, htons(plist->port));
        if (*plist->user || *plist->pass) {
            PSTDERR(" [u=%s,p=%s]", plist->user, plist->pass);
        }
        PSTDERR("\n");
    }
}

void DUMP_PROXY_DATA_LIST(proxy_data *plist, unsigned int count) {
    DUMP_PROXY_DATA_LIST_PREFIX(plist, count, "PDATA:");
}

void DUMP_PROXY_CHAIN_PREFIX(proxy_chain *pchain, const char* prefix) {
    char buff[32] = {'\0'};
    strcat(strcat(buff, prefix), "PCHAIN:");
    prefix = buff;
    PDEBUG("%s[name: \"%s\"]\n", prefix, pchain->name);
    PDEBUG("%schain type: %s\n", prefix, chain_type_strmap[pchain->ct]);
    PDEBUG("%stcp_read_time_out: %d\n", prefix, pchain->tcp_read_time_out);
    PDEBUG("%stcp_connect_time_out: %d\n", prefix, pchain->tcp_connect_time_out);
    PDEBUG("%smax_chain: %d\n", prefix, pchain->max_chain);
    PDEBUG("%soffset: %d\n", prefix, pchain->offset);
    PDEBUG("%scount: %d\n", prefix, pchain->count);
    DUMP_PROXY_DATA_LIST_PREFIX(pchain->pd, pchain->count, prefix);
}

void DUMP_PROXY_CHAIN(proxy_chain *pchain) {
    DUMP_PROXY_CHAIN_PREFIX(pchain, "");
}

void DUMP_PROXY_CHAIN_LIST(proxy_chain_list *pc_list) {
    const char *prefix = "PCLIST:";
    int i = 0;
    PDEBUG("%schain type (default): %s\n", prefix, chain_type_strmap[pc_list->ct]);
    PDEBUG("%stcp_read_time_out: %d\n", prefix, pc_list->tcp_read_time_out);
    PDEBUG("%stcp_connect_time_out: %d\n", prefix, pc_list->tcp_connect_time_out);
    PDEBUG("%sremote_dns_subnet: %d\n", prefix, pc_list->remote_dns_subnet);
    PDEBUG("%sselected chain: %s\n", prefix, (pc_list->selected)?pc_list->selected->name:NULL);
    PDEBUG("%snum_localnet_addr: %u\n", prefix, (unsigned int)pc_list->num_localnet_addr);
    PDEBUG("%schain list count: %d\n", prefix, pc_list->count);
    for (; i < pc_list->count; i++) {
        //~ DUMP_PROXY_CHAIN(pc_list->pc[i]);
        DUMP_PROXY_CHAIN_PREFIX(pc_list->pc[i], prefix);
    }
}

#endif
