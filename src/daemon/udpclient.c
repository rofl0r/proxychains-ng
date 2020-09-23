#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "../remotedns.h"
#include "../ip_type.h"

int main() {
	int fd;
	int port = 1053;
	char srvn[] = "127.0.0.1";
	struct sockaddr_in srva = {.sin_family = AF_INET, .sin_port = htons(port)};
	inet_pton(AF_INET, srvn, &srva.sin_addr);
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	char namebuf[260];
	while(fgets(namebuf, sizeof namebuf, stdin)) {
		size_t l = strlen(namebuf);
		if(namebuf[l-1] == '\n') {
			l--;
			namebuf[l] = 0;
		}
		struct at_msg msg = {0};
		unsigned msglen;
		if(isdigit(namebuf[0])) {
			msglen = 4;
			msg.h.msgtype = ATM_GETNAME;
			inet_aton(namebuf, (void*) &msg.m.ip);
		} else {
			msglen = l+1;
			msg.h.msgtype = ATM_GETIP;
			memcpy(msg.m.host, namebuf, msglen);
		}
		msg.h.datalen = htons(msglen);
		sendto(fd, &msg, sizeof(msg.h)+msglen, 0, (void*)&srva, sizeof(srva));
		char rcvbuf[512];
		recvfrom(fd, rcvbuf, sizeof rcvbuf, 0, (void*)0, (void*)0);
	}
}
