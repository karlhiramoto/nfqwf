#ifndef CONTENT_FILTER_H
#define CONTENT_FILTER_H 1

#ifdef HAVE_CONFIG_H
#include "nfq-proxy-config.h"
#endif

#include <stdbool.h>
#include <stdint.h>

#include "Object.h"

/**
* @ingroup Object
* @defgroup ProxyConfig Main configuration object
* @{
*/

struct ProxyConfig;

void ProxyConfig_get(struct ProxyConfig *conf);

void ProxyConfig_put(struct ProxyConfig **conf);

struct ProxyConfig* ProxyConfig_new(void);

int ProxyConfig_loadConfig(struct ProxyConfig* conf, const char *xml);

uint16_t ProxyConfig_getHighQNum(struct ProxyConfig* conf);

uint16_t ProxyConfig_getLowQNum(struct ProxyConfig* conf);

void ProxyConfig_setHighQNum(struct ProxyConfig* conf, uint16_t num);

void ProxyConfig_setLowQNum(struct ProxyConfig* conf, uint16_t num);

/** @} */
#endif