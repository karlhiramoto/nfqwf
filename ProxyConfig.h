#ifndef CONTENT_FILTER_H
#define CONTENT_FILTER_H 1

#ifdef HAVE_CONFIG_H
#include "nfq-proxy-config.h"
#endif

#include <stdbool.h>
#include <stdint.h>


/**
* @ingroup Object
* @defgroup ProxyConfig Main configuration object
* @{
*/

struct ProxyConfig
{
	OBJECT_COMMON

	/** We will use the queue range from low to high.
	See "man iptables" --queue-balance */
	uint16_t low_queue_id;
	uint16_t high_queue_id;
	
	struct ContentFilter *cf; /* content filter object */
};

/** @} */
#endif