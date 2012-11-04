#define PROXYCHAINS_CONF_FILE_ENV_VAR "PROXYCHAINS_CONF_FILE"
#define PROXYCHAINS_QUIET_MODE_ENV_VAR "PROXYCHAINS_QUIET_MODE"
#define PROXYCHAINS_CONF_FILE "proxychains.conf"
#define LOG_PREFIX "[proxychains] "
#ifndef SYSCONFDIR
#define SYSCONFDIR "/etc"
#endif

#include <stddef.h>

char *get_config_path(char* default_path, char* pbuf, size_t bufsize);

//RcB: DEP "common.c"