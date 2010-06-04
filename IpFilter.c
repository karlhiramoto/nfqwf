#include <stdlib.h>
#include <string.h>

#ifdef HAVE_CONFIG_H
#include "nfq-web-filter-config.h"
#endif



#include <netinet/in.h>
#include <arpa/inet.h>

#include "Filter.h"
#include "FilterType.h"
#include "HttpReq.h"
#include "HttpConn.h"
#include "nfq_proxy_private.h"

/**
* @ingroup FilterObject
* @defgroup IPFilter IP Filter Object
* @{
*/

struct IpFilter
{
	/** Base class members */
	FILTER_OBJECT_COMMON;

	/** IP address to filter */
	in_addr_t ip;

	/** Mask to apply to filter */
	in_addr_t mask;

	/** Match the Source IP if true, else destination IP */
	bool match_src;
};


/** To clone any private data*/
static int IpFilter_clone(struct Filter *dst, struct Filter *src)
{
	return 0;
}

static int IpFilter_constructor(struct Filter *fobj)
{
	return 0;
}

#define ADDR_STR "address"
#define MASK_STR "mask"

// FIXME  for quick prototype use char * later use real XML
static int IpFilter_load_from_xml(struct Filter *fobj, xmlNode *node)
{
	int ret;
	struct IpFilter *ipfo = (struct IpFilter *) fobj; /* IP filter object */
	xmlChar *prop = NULL;
	char addr[INET_ADDRSTRLEN+2];
	char mask[INET_ADDRSTRLEN+2];

	DBG(5, "Loading XML config id=%d\n", Filter_getFilterId(fobj));
	// set defaults
	ipfo->mask = 0xFFFFFFFF; 
	ipfo->match_src = false;

	prop = xmlGetProp(node, BAD_CAST ADDR_STR);
	if (!prop || (strlen((char*)prop) < 4)) {
		ERROR(" ip/filter objects MUST have '%s' XML props \n", ADDR_STR);
		return -1;
	}
	DBG(5, "ip addr str = '%s'\n", (char*)prop);
	ret = inet_pton(AF_INET,(const char*) prop, &ipfo->ip);
	if (ret < 1) {
		ERROR("Failed to get IP Address '%s'\n", (char*) prop);
	}
	xmlFree(prop);

	prop = xmlGetProp(node, BAD_CAST MASK_STR);
	if (prop && (strlen((char*)prop) > 4) ) {
		
		ret = inet_pton(AF_INET,(char*) prop, &ipfo->mask);
		if (ret < 1) {
			ERROR("Failed to get Mask '%s'\n", (char*) prop);
			xmlFree(prop);
			return -1;
		}
		xmlFree(prop);
	}

	// mask of extra bits
	ipfo->ip &= ipfo->mask;

	DBG(2, "Loaded IP Filter object ID=%d IP=0x%08X='%s' Mask=0x%08X='%s'\n",
		Filter_getFilterId(fobj),
		ipfo->ip,
		inet_ntop(AF_INET, &ipfo->ip, addr, sizeof(addr)),
		ipfo->mask,
		inet_ntop(AF_INET, &ipfo->mask, mask, sizeof(mask)));
	return 0;

}

static int IpFilter_matches_req(struct Filter *fobj, struct HttpReq *req)
{
	struct HttpConn *con = req->con;
	struct IpFilter *ipfo = (struct IpFilter *) fobj; /* IP filter object */

	if (ipfo->match_src) {
		// match source IP address
		if ( (con->tuple.src_ip & ipfo->mask) == ipfo->ip)
			return 1;
	} else {
		// match destination IP address
		if ( (con->tuple.dst_ip & ipfo->mask) == ipfo->ip)
			return 1;
	}

	return 0;
}

static struct Object_ops obj_ops = {
	.obj_type           = "filter/ip",
	.obj_size           = sizeof(struct IpFilter),
};

static struct Filter_ops IpFilter_obj_ops = {
	.ops                = &obj_ops,
	.foo_constructor	= IpFilter_constructor,
	.foo_clone          = IpFilter_clone,
	.foo_load_from_xml  = IpFilter_load_from_xml,
	.foo_matches_req    = IpFilter_matches_req,
};


/**
* Initialization function to register this filter type.
*/
static void __init IpFilter_init(void)
{
	DBG(5, "init ip_filter\n");
	FilterType_register(&IpFilter_obj_ops);
}

/** @}
end of Object file
*/

