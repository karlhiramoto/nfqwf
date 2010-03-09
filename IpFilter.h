#ifndef IP_FILTER_OBJECT_H
#define IP_FILTER_OBJECT_H

#include <linux/in.h>
#include "Filter.h"
#include "nfq_proxy_private.h"

struct IpFilter
{
	FILTER_OBJECT_COMMON
	in_addr_t ip;
	in_addr_t mask;
};

extern struct Filter_ops IpFilter_obj_ops;

#endif /* IP_FILTER_OBJECT_H */

