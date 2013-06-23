#ifndef COMMON_H
#define COMMON_H

#define PROXYCHAINS_CONF_FILE_ENV_VAR "PROXYCHAINS_CONF_FILE"
#define PROXYCHAINS_QUIET_MODE_ENV_VAR "PROXYCHAINS_QUIET_MODE"
#define PROXYCHAINS_CONF_FILE "proxychains.conf"
#define LOG_PREFIX "[proxychains] "
#ifndef SYSCONFDIR
#define SYSCONFDIR "/etc"
#endif

#include <stddef.h>

extern const char *proxy_type_strmap[];
extern const char *chain_type_strmap[];
extern const char *proxy_state_strmap[];

char *get_config_path(char* default_path, char* pbuf, size_t bufsize);
void pc_stringfromipv4(unsigned char *ip_buf_4_bytes, char *outbuf_16_bytes);

//RcB: DEP "common.c"
#endif
