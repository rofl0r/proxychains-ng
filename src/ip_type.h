#ifndef IP_TYPE_H
#define IP_TYPE_H

#include <stdint.h>

typedef union {
	unsigned char octet[4];
	uint32_t as_int;
} ip_type4;

typedef struct {
	union {
		ip_type4 v4;
		unsigned char v6[16];
	} addr;
	char is_v6;
} ip_type;

#define IPT4_INT(X) (ip_type4){.as_int = (X)}
#define IPT4_INVALID IPT4_INT(-1)

#define IPT4_BYTES(A,B,C,D) (ip_type4){.octet = {(A), (B), (C), (D)} }
#define IPT4_LOCALHOST IPT4_BYTES(127,0,0,1)

#endif
