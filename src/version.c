#include "version.h"
static const char version[] = VERSION;
const char *proxychains_get_version(void) {
	return version;
}

