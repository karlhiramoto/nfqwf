#ifndef PROXY_CONFIG_H
#define PROXY_CONFIG_H 1

#ifdef HAVE_CONFIG_H
#include "nfq-web-filter-config.h"
#endif

#include <stdbool.h>
#include <stdint.h>

#include "Object.h"

/* forward declaration */
struct ProxyConfig;


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


void ProxyConfig_get(struct ProxyConfig *conf);

void ProxyConfig_put(struct ProxyConfig **conf);

struct ProxyConfig* ProxyConfig_new(void);

int ProxyConfig_loadConfig(struct ProxyConfig* conf, const char *xml);


struct ContentFilter * ProxyConfig_getContentFilter(struct ProxyConfig* conf);

uint16_t ProxyConfig_getHighQNum(struct ProxyConfig* conf);

uint16_t ProxyConfig_getLowQNum(struct ProxyConfig* conf);

void ProxyConfig_setHighQNum(struct ProxyConfig* conf, uint16_t num);

void ProxyConfig_setLowQNum(struct ProxyConfig* conf, uint16_t num);

struct ContentFilter* ProxyConfig_contentFilter(struct ProxyConfig* conf);

enum non_http_action ProxyConfig_getNonHttpAction(struct ProxyConfig* conf);

#endif
