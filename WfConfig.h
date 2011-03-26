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

#ifndef PROXY_CONFIG_H
#define PROXY_CONFIG_H 1

#ifdef HAVE_CONFIG_H
#include "nfq-web-filter-config.h"
#endif

#include <stdbool.h>
#include <stdint.h>

#include "Object.h"

/* forward declaration */
struct WfConfig;


/**
What to do with a packet that is part of a connection,
that does not comply with HTTP protocol.
Note the default RESET is first so that the calloc() will initialize it.
*/
enum non_http_action {
	non_http_action_reset, /// send TCP reset for packets in this connection
	non_http_action_accept, ///Accept packet
	non_http_action_drop,  /// drop packet
	non_http_action_last  /// last invalid.
};


void WfConfig_get(struct WfConfig *conf);

void WfConfig_put(struct WfConfig **conf);

struct WfConfig* WfConfig_new(void);

int WfConfig_loadConfig(struct WfConfig* conf, const char *xml);


struct ContentFilter * WfConfig_getContentFilter(struct WfConfig* conf);

uint16_t WfConfig_getHighQNum(struct WfConfig* conf);

uint16_t WfConfig_getLowQNum(struct WfConfig* conf);

void WfConfig_setHighQNum(struct WfConfig* conf, uint16_t num);

void WfConfig_setLowQNum(struct WfConfig* conf, uint16_t num);

struct ContentFilter* WfConfig_contentFilter(struct WfConfig* conf);

enum non_http_action WfConfig_getNonHttpAction(struct WfConfig* conf);

unsigned int WfConfig_getMaxFiltredFileSize(struct WfConfig* conf);

unsigned int WfConfig_getPktBuffSize(struct WfConfig* conf);

const char *WfConfig_getTmpDir(struct WfConfig* conf);

#endif
