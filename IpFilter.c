#include <stdlib.h>

#ifdef HAVE_CONFIG_H
#include "nfq-proxy-config.h"
#endif


#include <linux/in.h>
#include <arpa/inet.h>

#include "Filter.h"
#include "FilterType.h"
//#include "IpFilter.h"
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


/** To clone any private data*/
int IpFilter_clone(struct Filter *dst, struct Filter *src)
{
	return 0;
}

int IpFilter_constructor(struct Filter *fobj)
{
	return 0;
}

// FIXME  for quick prototype use char * later use real XML
int IpFilter_load_from_xml(struct Filter *fobj, const char *xml)
{
	int ret;
	struct IpFilter *ipfo = (struct IpFilter *) fobj; /* IP filter object */
	DBG(5, "Loading XML config ='%s'\n", xml);
	ipfo->mask = 0xFFFFFFFF;

	ret = inet_pton(AF_INET, xml, &ipfo->ip);
	if (ret == 1)
		return 0;
	else return -1;
}

static struct Object_ops obj_ops = {
	.obj_name           = "filter/ip",
	.obj_size           = sizeof(struct IpFilter),
};

static struct Filter_ops IpFilter_obj_ops = {
	.ops                = &obj_ops,
	.foo_constructor	= IpFilter_constructor,
	.foo_clone          = IpFilter_clone,
	.foo_load_from_xml  = IpFilter_load_from_xml,
};



static void __init IpFilter_init(void)
{
	DBG(5, "init ip_filter\n");
	FilterType_register(&IpFilter_obj_ops);
	// TODO register to some kind of available filter list.
}

/** @}
end of Object file
*/

