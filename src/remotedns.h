#ifndef REMOTEDNS_H
#define REMOTEDNS_H

#include <unistd.h>
#include "ip_type.h"

#define MSG_LEN_MAX 256

enum at_msgtype {
	ATM_GETIP = 0,
	ATM_GETNAME,
	ATM_FAIL,
	ATM_EXIT,
};

struct at_msghdr {
	unsigned char msgtype; /* at_msgtype */
	char reserved;
	unsigned short datalen;
};

struct at_msg {
	struct at_msghdr h;
	union {
		char host[260];
		ip_type4 ip;
	} m;
};

#endif

