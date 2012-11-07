#ifndef IP_TYPE_H
#define IP_TYPE_H

#include <stdint.h>

typedef union {
	unsigned char octet[4];
	uint32_t as_int;
} ip_type;

extern const ip_type ip_type_invalid;
extern const ip_type ip_type_localhost;

//RcB: DEP "ip_type.c"
#endif
