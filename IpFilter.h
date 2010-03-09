#ifndef IP_FILTER_OBJECT_H
#define IP_FILTER_OBJECT_H

#include <linux/in.h>
#include "Filter.h"
#include "nfq_proxy_private.h"

/**
* @ingroup FilterObject
* @defgroup IPFilter IP Filter Object
* @{
*/

struct IpFilter
{
	FILTER_OBJECT_COMMON
	in_addr_t ip; /** IP address to filter */
	in_addr_t mask; /** Mask to apply to filter */
};

extern struct Filter_ops IpFilter_obj_ops;


/** @}
end of Object file
*/
#endif /* IP_FILTER_OBJECT_H */

