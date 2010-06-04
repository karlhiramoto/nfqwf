#ifndef CONTENT_FILTER_H
#define CONTENT_FILTER_H 1

#ifdef HAVE_CONFIG_H
#include "nfq-web-filter-config.h"
#endif

#include <stdbool.h>
#include <libxml/tree.h>
#include "Filter.h"
#include "Rules.h"

/**
* @ingroup Object
* @defgroup ContentFilter Content Filter.  Combine rules and filter objets
* @{
*/
struct ContentFilter;

void ContentFilter_get(struct ContentFilter *cf);

void ContentFilter_put(struct ContentFilter **cf);

struct ContentFilter* ContentFilter_new(void);


int ContentFilter_loadConfig(struct ContentFilter* cf, xmlNode *node);

int ContentFilter_requestStart(struct ContentFilter* cf, struct HttpReq *req);

int ContentFilter_getRequestVerdict(struct ContentFilter* cf, struct HttpReq *req);

int ContentFilter_filterStream(struct ContentFilter* cf, struct HttpReq *req,
		const unsigned char *data_stream, unsigned int length);

int ContentFilter_fileScan(struct ContentFilter* cf, struct HttpReq *req);

bool ContentFilter_hasFileFilter(struct ContentFilter* cf);

/** @} */
#endif
