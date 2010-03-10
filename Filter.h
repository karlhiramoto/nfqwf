#ifndef FILTER_OBJECT_H
#define FILTER_OBJECT_H

#ifdef HAVE_CONFIG_H
#include "nfq-proxy-config.h"
#endif


#include "nfq_proxy_private.h"
#include "Object.h" // generic object

#define FILTER_OBJECT_COMMON \
OBJECT_COMMON \
struct Filter_ops *fo_ops; \

/**
* @ingroup Object
* @defgroup FilterObject Filter Object
* @{
*/



struct Filter
{
	FILTER_OBJECT_COMMON
};

struct rule;
struct HttpReq;

struct Filter_ops
{
	/* parents ops */
	struct Object_ops *ops;

	/**
	  Optional size of private data that will be assiged per HTTP request.
	  This can be used to store state.
	  This is the inital size of the pointer passed in, the fillter object
	  may relloc() if it wishes. 
	*/
	int private_req_data_size;
	
	/**
	* Optional callback(virtual method) to init/allocate any private data
	*/
	int (*foo_constructor)(struct Filter *);

	/**
	* Optional callback(virtual method) to free any private data
	*/
	int (*foo_destructor)(struct Filter *);

	/*optional callback to clone private data */
	int (*foo_clone)(struct Filter *dst, struct Filter *src);

	/*optional callback to compare two filters */
	int (*foo_compare)(struct Filter *dst, struct Filter *src);

	/** Used to preload or start any async operation
	This is called when request comes from the client
	NOTE the filter object will be responsible for maintaining its own request table
	*/
	int (*foo_request_start)(struct Filter *obj, struct HttpReq *, void *priv_req_data);
	
	/** @brief Check if filter object matches request
	    This is called when request comes back from server.
	    @param obj   This filter object
	    @param HttpReq Http Request we are going to filter
	    @param priv_req_data double pointer to data private
	    to this filter object and unique to this http request
	    @returns 1 on match, 0 no match, or -errno
	*/
	int (*foo_matches_req)(struct Filter *obj, struct HttpReq *, void *priv_req_data);


	// FIXME some kind of filter for AV
	int (*foo_file_filter)(struct Filter *obj, struct HttpReq *, int *fd);
	
	/* to load xml.. TODO use libxml2 type */
	int (*foo_load_from_xml)(struct Filter *, const char *xml);
	
	/*for debug */
	int (*foo_print)(struct Filter *);
};

/**
* @name Reference Management
* @{
*/
struct Filter *Filter_alloc(struct Filter_ops *ops);

void Filter_free(struct Filter **obj);

void Filter_get(struct Filter *obj);
void Filter_put(struct Filter **obj);

/**
* Check whether this object is used by multiple users
* @param obj  object to check
* @return true or false
*/
bool Filter_shared(struct Filter *obj);

/** @}
end of refrence management
*/

/**
* Load filter object from XML config
* @param obj  Filter object
* @param xml  xml config   FIXME change xml to use libxml2
*/
int Filter_fromXml(struct Filter *obj, const char *xml);

/** @}
end of Object file
*/

#endif /* FILTER_OBJECT_H */

