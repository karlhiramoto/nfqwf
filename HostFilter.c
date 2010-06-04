#define _GNU_SOURCE 
#include <string.h>
#include <stdlib.h>

#ifdef HAVE_CONFIG_H
#include "nfq-web-filter-config.h"
#endif

#include <fnmatch.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include "Filter.h"
#include "FilterType.h"
#include "HttpReq.h"
#include "nfq_proxy_private.h"
#include "HttpConn.h"
#include "PrivData.h"

/**
* @ingroup FilterObject
* @defgroup HostFilter Domain Filter Object
* @{
*/

struct HostFilter
{
	FILTER_OBJECT_COMMON
	char *host; /**< Hostname or Domain to filter */
};

#if 0
/** To clone any private data*/
static int HostFilter_clone(struct Filter *dst, struct Filter *src)
{
	struct HostFilter *sf = (struct HostFilter *) src; /* filter object */
	struct HostFilter *df = (struct HostFilter *) dst; /* filter object */

	if (df->host) {
		free(df->host);
		df->host = NULL;
	}

	if (sf->host) {
		df->host = strdup(sf->host);
	}
	return 0;
}


static int HostFilter_constructor(struct Filter *fobj)
{
	return 0;
}
#endif
static int HostFilter_destructor(struct Filter *fobj)
{
	struct HostFilter *fo = (struct HostFilter *) fobj; /* filter object */

	if (fo->host) {
		free(fo->host);
		fo->host = NULL;
	}

	return 0;
}

#define HOST_STR "host"

// FIXME  for quick prototype use char * later use real XML
static int HostFilter_load_from_xml(struct Filter *fobj, xmlNode *node)
{
	struct HostFilter *fo = (struct HostFilter *) fobj; /* filter object */
	xmlChar *prop = NULL;
	
	DBG(5, "Loading XML config\n");

	prop = xmlGetProp(node, BAD_CAST HOST_STR);
	if (!prop) {
		ERROR(" filter/host objects MUST have '%s' XML props \n", HOST_STR);
		return -1;
	}

	fo->host = strdup((char*) prop);
	xmlFree(prop);

	if (!fo->host)
		return -1;

	DBG(2, "Loaded Host Filter object ID=%d host='%s'\n",
		Filter_getFilterId(fobj),
		fo->host);

	return 0;
}

//Note saving to the private con data will be faster, when
// there are multiple requests per connection and the private data lookup
// is faster than the fnmatch()
#define PRIV_CON_DATA 1

#ifdef PRIV_CON_DATA
static int HostFilter_start_req(struct Filter *fobj, struct HttpReq *req)
{
	struct HostFilter *fo = (struct HostFilter *) fobj; /* Host filter object */
	struct HttpConn *con = req->con;
	void *data;

	if (con->cur_request > 1) {
		DBG(7, "multiple requests to same host filter_id=%d\n", Filter_getObjId(fobj));
		return 0;
	}
	data = PrivData_newData(con->priv_data, Filter_getObjId(fobj), sizeof(int), free);
	if (!data) {
		ERROR_FATAL("Missing private data id=%d\n", Filter_getObjId(fobj));
		return -1;
	}

	if (!req->host)
		ERROR_FATAL("Host NULL, BUG\n");

	if (fnmatch(fo->host, req->host, FNM_CASEFOLD))
		(*(int *)data) = 0; // no match
	else
		(*(int *)data) = 1; // match

	return 0; // OK
}
#endif
static int HostFilter_matches_req(struct Filter *fobj, struct HttpReq *req)
{
	#ifdef PRIV_CON_DATA
	struct HttpConn *con = req->con;
	void *data;
	// every request in the same connection will be to the same host so use saved value.
	data = PrivData_getData(con->priv_data, Filter_getObjId(fobj));
	if (!data) {
		WARN("Missing private data with id=%d\n", Filter_getObjId(fobj));
		return 0;
	}
	// return saved match
	return (*(int *)data);
	#else
	struct HostFilter *fo = (struct HostFilter *) fobj; /* Host filter object */

	DBG(5, "check if req host='%s' contains = '%s'\n", req->host, fo->host);
	if (!req->host)
		ERROR_FATAL("Host NULL, BUG\n");

	if (!fnmatch(fo->host, req->host, FNM_CASEFOLD))
		return 1;

	return 0;
	#endif
}
static struct Object_ops obj_ops = {
	.obj_type           = "filter/host",
	.obj_size           = sizeof(struct HostFilter),
};

static struct Filter_ops HostFilter_obj_ops = {
	.ops                = &obj_ops,
	.foo_destructor     = HostFilter_destructor,
/*	.foo_constructor	= HostFilter_constructor, */
	.foo_load_from_xml  = HostFilter_load_from_xml,
#if PRIV_CON_DATA
	.foo_request_start  = HostFilter_start_req,
#endif	
	.foo_matches_req    = HostFilter_matches_req,
};


/**
* Initialization function to register this filter type.
*/
static void __init HostFilter_init(void)
{
	DBG(5, "init Host/Domain filter\n");
	FilterType_register(&HostFilter_obj_ops);
}

/** @} */

