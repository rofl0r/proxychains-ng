#include "common.h"
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

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

// stolen from libulz (C) rofl0r
void pc_stringfromipv4(unsigned char *ip_buf_4_bytes, char *outbuf_16_bytes) {
	unsigned char *p;
	char *o = outbuf_16_bytes;
	unsigned char n;
	for(p = ip_buf_4_bytes; p < ip_buf_4_bytes + 4; p++) {
		n = *p;
		if(*p >= 100) {
			if(*p >= 200)
				*(o++) = '2';
			else
				*(o++) = '1';
			n %= 100;
		}
		if(*p >= 10) {
			*(o++) = (n / 10) + '0';
			n %= 10;
		}
		*(o++) = n + '0';
		*(o++) = '.';
	}
	o[-1] = 0;
}

static int check_path(char *path) {
	if(!path)
		return 0;
	return access(path, R_OK) != -1;
}

char *get_config_path(char* default_path, char* pbuf, size_t bufsize) {
	char buf[512];
	// top priority: user defined path
	char *path = default_path;
	if(check_path(path))
		goto have;

	// priority 1: env var PROXYCHAINS_CONF_FILE
	path = getenv(PROXYCHAINS_CONF_FILE_ENV_VAR);
	if(check_path(path))
		goto have;

	// priority 2; proxychains conf in actual dir
	path = getcwd(buf, sizeof(buf));
	snprintf(pbuf, bufsize, "%s/%s", path, PROXYCHAINS_CONF_FILE);
	path = pbuf;
	if(check_path(path))
		goto have;

	// priority 3; $HOME/.proxychains/proxychains.conf
	path = getenv("HOME");
	snprintf(pbuf, bufsize, "%s/.proxychains/%s", path, PROXYCHAINS_CONF_FILE);
	path = pbuf;
	if(check_path(path))
		goto have;

	// priority 4: $SYSCONFDIR/proxychains.conf
	path = SYSCONFDIR "/" PROXYCHAINS_CONF_FILE;
	if(check_path(path))
		goto have;

	// priority 5: /etc/proxychains.conf
	path = "/etc/" PROXYCHAINS_CONF_FILE;
	if(check_path(path))
		goto have;

	perror("couldnt find configuration file");
	exit(1);

	return NULL;
	have:
	return path;
}
