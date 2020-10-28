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

/* isnumericipv4() taken from libulz */
int pc_isnumericipv4(const char* ipstring) {
	size_t x = 0, n = 0, d = 0;
	int wasdot = 0;
	while(1) {
		switch(ipstring[x]) {
			case 0: goto done;
			case '.':
				if(!n || wasdot) return 0;
				d++;
				wasdot = 1;
				break;
			case '0': case '1': case '2': case '3': case '4':
			case '5': case '6': case '7': case '8': case '9':
				n++;
				wasdot = 0;
				break;
			default:
				return 0;
		}
		x++;
	}
	done:
	if(d == 3 && n >= 4 && n <= 12) return 1;
	return 0;
}

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
    
    // priority 3b: ~/config/settings/proxychains.conf (for haiku)
	path = getenv("HOME");
	snprintf(pbuf, bufsize, "%s/config/settings/%s", path, PROXYCHAINS_CONF_FILE);
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
