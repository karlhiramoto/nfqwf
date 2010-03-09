#include <stdlib.h>

#ifdef HAVE_CONFIG_H
#include "nfq-proxy-config.h"
#endif

#include "Filter.h"
#include "FilterType.h"
#include "IpFilter.h"
#include "nfq_proxy_private.h"


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
	DBG(5, "Loading XML config\n");
	return 0;
}

struct Object_ops obj_ops = {
	.obj_name           = "filter/ip",
	.obj_size           = sizeof(struct IpFilter),
};

struct Filter_ops IpFilter_obj_ops = {
	.ops            = &obj_ops,
	.foo_constructor	= IpFilter_constructor,
	.foo_clone          = IpFilter_clone,
	.foo_load_from_xml  = IpFilter_load_from_xml,
};


/**
* @name Allocation/Freeing
* @{
*/

struct IpFilter *IpFilter_alloc(void)
{
	return (struct IpFilter *) Filter_alloc(&IpFilter_obj_ops);
}

void IpFilter_get(struct IpFilter *obj)
{
	Filter_get((struct Filter *) obj);
}

void IpFilter_put(struct IpFilter *obj)
{
	Filter_put((struct Filter *) obj);
}

static void __init IpFilter_init(void)
{
	DBG(5, "init ip_filter\n");
	FilterType_register(&IpFilter_obj_ops);
	// TODO register to some kind of available filter list.
}
