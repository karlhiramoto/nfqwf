#define _GNU_SOURCE 
#include <string.h>
#include <stdlib.h>

#ifdef HAVE_CONFIG_H
#include "nfq-web-filter-config.h"
#endif

#include <time.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include "Filter.h"
#include "FilterType.h"
#include "HttpReq.h"
#include "nfq_proxy_private.h"
#include "HttpConn.h"
#define DAYS_IN_WEEK 7
/**
* @ingroup FilterObject
* @defgroup TimeFilter Domain Filter Object
* @{
*/

struct TimeFilter
{
	FILTER_OBJECT_COMMON
	bool dow[DAYS_IN_WEEK]; /* Days of week */ 
	uint8_t from_min; /* 0 to 23 */
	uint8_t from_hour; /* 0 to 59 */
	uint8_t to_min; /* 0 to 23 */
	uint8_t to_hour; /* 0 to 59 */
};
#define HOST_STR "host"

static int TimeFilter_load_from_xml(struct Filter *fobj, xmlNode *node)
{
	struct TimeFilter *filt = (struct TimeFilter *) fobj; /* filter object */
	xmlChar *prop = NULL;
	const char *days[] = { "sun", "mon", "tue", "wed", "thu", "fri", "sat", "" };
	int i;
	int ret;
	DBG(5, "Loading XML config\n");

	for (i = 0; i < DAYS_IN_WEEK; i++) {
		prop = xmlGetProp(node, BAD_CAST days[i]);
		if (prop) {
			filt->dow[i] = atoi((const char *)prop);
			xmlFree(prop);
		} else {
			filt->dow[i] = false;
		}
	}

	prop = xmlGetProp(node, BAD_CAST "from");
	if (prop) {
		ret = sscanf((const char*) prop, "%hhd:%hhd", &filt->from_hour, &filt->from_min);
		if (ret != 2) {
			ERROR("parsing time 'from'\n");
			filt->from_hour = 0;
			filt->from_min = 0;
		}
		xmlFree(prop);
	} else {
		filt->from_hour = 0;
		filt->from_min = 0;
	}
	
	prop = xmlGetProp(node, BAD_CAST "to");
	if (prop) {
		ret = sscanf((const char*) prop, "%hhd:%hhd", &filt->to_hour, &filt->to_min);
		if (ret != 2) {
			ERROR("parsing time 'to'\n");
			filt->to_hour = 23;
			filt->to_min = 59;
		}
		xmlFree(prop);
	} else {
		filt->to_hour = 23;
		filt->to_min = 59;
	}

	DBG(2, "Loaded TimeFilter object ID=%d "
		"su=%d mo=%d tu=%d we=%d th=%d fr=%d sa=%d from=%02d:%02d to=%02d:%02d\n",
		Filter_getFilterId(fobj), filt->dow[0], filt->dow[1], filt->dow[2],
		filt->dow[3], filt->dow[4], filt->dow[5], filt->dow[6],
		filt->from_hour, filt->from_min, filt->to_hour, filt->to_min);

	return 0;
}

static int time_filter_matches(struct TimeFilter *filt, struct HttpReq *req)
{
	struct HttpConn *con = req->con;
	struct tm tm;

	if (!localtime_r(&con->last_pkt, &tm)) {
		ERROR(" calling localtime\n");
	}

	if(filt->dow[tm.tm_wday]) {
		// day of week matches
		if (tm.tm_hour >= filt->from_hour && tm.tm_hour <= filt->to_hour &&
			tm.tm_min >= filt->from_min && tm.tm_min <= filt->to_min) {
			// time matches
			return 1;
		}
	}
	return 0;
}

//Note saving to the private con data may be faster, when
// there are multiple requests per connection and the private data lookup
// NOTE if private connection data is used, then we only check the time at the
// start of the connection, not at the start of each request,
// A long lived connection may bypass the checks
// #define PRIV_CON_DATA 1

#ifdef PRIV_CON_DATA
static int TimeFilter_start_req(struct Filter *fobj, struct HttpReq *req)
{
	struct TimeFilter *filt = (struct TimeFilter *) fobj; /* Host filter object */
	struct HttpConn *con = req->con;
	void *data;

	if (con->cur_request > 1) {
		DBG(7, "multiple requests to same host filter_id=%d\n", Filter_getObjId(fobj));
		return 0;
	}
	data = HttpConn_newPrivData(con, Filter_getObjId(fobj), sizeof(int));
	if (!data) {
		ERROR_FATAL("Missing private data id=%d\n", Filter_getObjId(fobj));
		return -1;
	}

	(*(int *)data) = time_filter_matches(filt, req);

	return 0; // OK
}
#endif
static int TimeFilter_matches_req(struct Filter *fobj, struct HttpReq *req)
{
	#ifdef PRIV_CON_DATA
	struct HttpConn *con = req->con;
	void *data;
	
	// every request in the same connection will be to the same host so use saved value.
	data = HttpConn_getPrivData(con, Filter_getObjId(fobj));
	if (!data) {
		ERROR_FATAL("Missing private data with id=%d\n", Filter_getObjId(fobj));
	}
	// return saved match
	return (*(int *)data);
	#else
	struct TimeFilter *filt = (struct TimeFilter *) fobj; /* Host filter object */

	return time_filter_matches(filt, req);
	#endif
}
static struct Object_ops obj_ops = {
	.obj_type           = "filter/time",
	.obj_size           = sizeof(struct TimeFilter),
};

static struct Filter_ops TimeFilter_obj_ops = {
	.ops                = &obj_ops,
#if 0
	.foo_destructor     = TimeFilter_destructor,
	.foo_constructor	= TimeFilter_constructor,
#endif
	.foo_load_from_xml  = TimeFilter_load_from_xml,
#if PRIV_CON_DATA
	.foo_request_start  = TimeFilter_start_req,
#endif	
	.foo_matches_req    = TimeFilter_matches_req,
};


/**
* Initialization function to register this filter type.
*/
static void __init TimeFilter_init(void)
{
	DBG(5, "init Time filter\n");
	FilterType_register(&TimeFilter_obj_ops);
}

/** @} */

