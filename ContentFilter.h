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

void ContentFilter_logReq(struct ContentFilter* cf, struct HttpReq *req);

/** @} */
#endif
