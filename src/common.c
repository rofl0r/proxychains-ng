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
    char *path = NULL;

    // top priority: user-defined path
    if (default_path && check_path(default_path)) {
        return default_path;
    }

    // priority 1: environment override
    path = getenv(PROXYCHAINS_CONF_FILE_ENV_VAR);
    if (check_path(path)) {
        return path;
    }

    // priority 2: XDG_CONFIG_HOME or fallback to ~/.config
    const char *xdg_config_home = getenv("XDG_CONFIG_HOME");
    const char *home = getenv("HOME");
    if (xdg_config_home) {
        snprintf(pbuf, bufsize, "%s/proxychains/%s", xdg_config_home, PROXYCHAINS_CONF_FILE);
        if (check_path(pbuf)) return pbuf;
    } else if (home) {
        snprintf(pbuf, bufsize, "%s/.config/proxychains/%s", home, PROXYCHAINS_CONF_FILE);
        if (check_path(pbuf)) return pbuf;
    }

    // priority 3: Haiku-style config location
    if (home) {
        snprintf(pbuf, bufsize, "%s/config/settings/%s", home, PROXYCHAINS_CONF_FILE);
        if (check_path(pbuf)) return pbuf;
    }

    // priority 4: system config via build-time sysconfdir
    path = SYSCONFDIR "/" PROXYCHAINS_CONF_FILE;
    if (check_path(path)) return path;

    // priority 5: final fallback
    path = "/etc/" PROXYCHAINS_CONF_FILE;
    if (check_path(path)) return path;

    perror("could not find configuration file");
    exit(1);
}
