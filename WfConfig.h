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

const char *WfConfig_getTmpDir(struct WfConfig* conf);

#endif
