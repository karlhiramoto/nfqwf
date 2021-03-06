/*
Copyright (C) <2010-2011> Karl Hiramoto <karl@hiramoto.org>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

#ifndef FILTER_OBJECT_H
#define FILTER_OBJECT_H

#ifdef HAVE_CONFIG_H
#include "nfq-web-filter-config.h"
#endif

#include <libxml/tree.h>

#include "nfq_wf_private.h"
#include "Object.h" // generic object


/**
* Common FilterObject Header
* This macro must be included as first member in every object,
* that inherits this FilterObject
*/
#define FILTER_OBJECT_COMMON \
OBJECT_COMMON; \
unsigned int filter_id; \
struct Filter_ops *fo_ops; \

/**
* @ingroup Object
* @defgroup FilterObject Filter Object
* @{
*/


/**
* @struct Filter
* @brief A generic filter object that other more specialized filter objects will inherit.
* @brief This will give us a kind of polymorphism.
*/
struct Filter
{
	FILTER_OBJECT_COMMON;
};

struct rule;
struct HttpReq;

/**
* @struct Filter_ops
* @brief FilterObject operations, defines various callbacks on filter objcets.
*/
struct Filter_ops
{
	/* parents ops */
	struct Object_ops *ops;

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

	/** OPTIONAL Used to preload or start any async operation
	This is called when request comes from the client
	NOTE the filter object will be responsible for maintaining its own request table
	*/
	int (*foo_request_start)(struct Filter *obj, struct HttpReq *);

	/** @brief Check if filter object matches request
	    This is called when the 1st packet of the request comes back from server.
	    @param obj   This filter object
	    @param HttpReq Http Request we are going to filter
	    @returns 1 on match, 0 no match, or -errno
	*/
	int (*foo_matches_req)(struct Filter *obj, struct HttpReq *);


	// filter for AV or other kind of filter on data stream
	int (*foo_stream_filter)(struct Filter *obj, struct HttpReq *,
			const unsigned char *data_stream, unsigned int length);


	/**
	* @brief file filer for Anti-virus or other file contents filter
	* @param obj  Filter object
	* @param HttpReq Http Request we are going to filter
	* @returns -1 on error, or enum Action  see  @link Action
	*/
	int (*foo_file_filter)(struct Filter *obj, struct HttpReq *);

	/**
	* @brief Load filter object from XML config
	* @param obj  Filter object
	* @param xml  Node that is the root of this, filter object,
	*             may have attributes and/or children.
	*/
	int (*foo_load_from_xml)(struct Filter *obj, xmlNode *node);

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

static inline void Filter_setFilterId(struct Filter *obj, unsigned int id) {
	obj->filter_id = id;
}
static inline unsigned int Filter_getFilterId(struct Filter *obj) {
	return obj->filter_id;
}
/** get Lower inherited  object  ID, NOTE should be read only */
static inline int Filter_getObjId(struct Filter *obj) {
	return obj->id;
}
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
* @param xml  Node that is the root of this, filter object,
*             may have attributes and/or children.
*/
int Filter_fromXml(struct Filter *obj, xmlNode *node);

/** @}
end of Object file
*/

#endif /* FILTER_OBJECT_H */

