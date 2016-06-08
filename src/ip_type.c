#include "ip_type.h"

const ip_type ip_type_invalid = { .addr.v4.as_int = -1 };
const ip_type ip_type_localhost = { .addr.v4.octet = {127, 0, 0, 1} };

