#include <stdlib.h>

#ifdef HAVE_CONFIG_H
#include "nfq-proxy-config.h"
#endif


#include <netinet/in.h>
#include <arpa/inet.h>

#include "Filter.h"
#include "FilterType.h"
#include "nfq_proxy_private.h"

/**
* @ingroup FilterObject
* @defgroup DomainFilter Domain Filter Object
* @{
*/

struct DomainFilter
{
	FILTER_OBJECT_COMMON
	char *domain; /** Domain to filter */
};


/** To clone any private data*/
int DomainFilter_clone(struct Filter *dst, struct Filter *src)
{
	return 0;
}

int DomainFilter_constructor(struct Filter *fobj)
{
	return 0;
}

// FIXME  for quick prototype use char * later use real XML
int DomainFilter_load_from_xml(struct Filter *fobj, const char *xml)
{

	return 0;
}

static struct Object_ops obj_ops = {
	.obj_name           = "filter/Domain",
	.obj_size           = sizeof(struct DomainFilter),
};

static struct Filter_ops DomainFilter_obj_ops = {
	.ops                = &obj_ops,
	.foo_constructor	= DomainFilter_constructor,
	.foo_clone          = DomainFilter_clone,
	.foo_load_from_xml  = DomainFilter_load_from_xml,
};


/**
* Initalization function to register this filter type.
*/
static void __init DomainFilter_init(void)
{
	DBG(5, "init Domain filter\n");
	FilterType_register(&DomainFilter_obj_ops);
	// TODO register to some kind of available filter list.
}

/** @} */

