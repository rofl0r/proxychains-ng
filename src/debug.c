
#ifdef DEBUG
# include "core.h"
# include "common.h"
# include "debug.h"
#include <arpa/inet.h>

void dump_proxy_chain(proxy_data *pchain, unsigned int count) {
	char ip_buf[INET6_ADDRSTRLEN];
	for (; count; pchain++, count--) {
		if(!inet_ntop(pchain->ip.is_v6?AF_INET6:AF_INET,pchain->ip.addr.v6,ip_buf,sizeof ip_buf)) {
			proxychains_write_log(LOG_PREFIX "error: ip address conversion failed\n");
			continue;
		}
		PDEBUG("[%s] %s %s:%d", proxy_state_strmap[pchain->ps],
		       proxy_type_strmap[pchain->pt], 
		       ip_buf, htons(pchain->port));
		if (*pchain->user || *pchain->pass) {
			PSTDERR(" [u=%s,p=%s]", pchain->user, pchain->pass);
		}
		PSTDERR("\n");
	}
}

void dump_buffer(unsigned char * data, size_t len){
	printf("buffer_dump[");
	for(int i=0; i<len; i++){
		printf("%d ", *(data+i));
	}
	printf("]\n");
}

void dump_relay_chains_list(udp_relay_chain_list list){
	udp_relay_chain* current;
	current = list.head;

	PDEBUG("relay chains list dump: \n");
	while(current != NULL){
		dump_relay_chain(current);
		current = current->next;
	}
}

void dump_relay_chain(udp_relay_chain* chain){
	printf("Chain %x: fd=%d\n", chain, chain->sockfd);
	udp_relay_node* current_node;
	current_node = chain->head;
	char ip_buf[INET6_ADDRSTRLEN];
	char ip_buf2[INET6_ADDRSTRLEN];
	while(current_node ){
		printf("\tNode%x", current_node);
		printf("[%s:%i]", inet_ntop(current_node->bnd_addr.is_v6?AF_INET6:AF_INET, current_node->bnd_addr.is_v6?(void*)current_node->bnd_addr.addr.v6:(void*)current_node->bnd_addr.addr.v4.octet, ip_buf2, sizeof(ip_buf2))  , ntohs(current_node->bnd_port));
		printf("(ctrl_fd%i-%s:%i)",  current_node->tcp_sockfd, inet_ntop(current_node->pd.ip.is_v6?AF_INET6:AF_INET, current_node->pd.ip.is_v6?(void*)current_node->pd.ip.addr.v6:(void*)current_node->pd.ip.addr.v4.octet, ip_buf, sizeof(ip_buf)) , ntohs(current_node->pd.port) );
		printf("\n");
		current_node = current_node->next;
	}

}
#else

// Do not allow this translation unit to end up empty
// for non-DEBUG builds, to satisfy ISO C standards.
typedef int __appease_iso_compilers__;

#endif
