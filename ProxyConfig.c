#include <stdlib.h>
#include <errno.h>
#include <string.h>

#ifdef HAVE_CONFIG_H
#include "nfq-proxy-config.h"
#endif

#include "ProxyConfig.h"
#include "FilterType.h"
#include "FilterList.h"
#include "Rules.h"
#include "nfq_proxy_private.h"

/**
* @ingroup Object
* @defgroup ProxyConfig ProxyConfig. Main configuration object
* @{
*/


struct ProxyConfig
{
	/** Base objects member variables */
	OBJECT_COMMON;

	/** We will use the queue range from low to high.
	See "man iptables" --queue-balance */
	uint16_t low_queue_num;
	uint16_t high_queue_num;
	char *error_page; 
	struct ContentFilter *cf; /* content filter object */
};

/**
* @name Reference Management
* @{
*/

/** Get a reference counter */
void ProxyConfig_get(struct ProxyConfig *conf) {
	Object_get((struct Object*) conf);
	DBG(4, "New reference to ProxyConfig %p refcount = %d\n",
		conf, conf->refcount);
}

/** Release reference counter */
void ProxyConfig_put(struct ProxyConfig **conf) {
	
	DBG(4, "removing Config reference to %p refcount = %d\n",
		*conf, (*conf)->refcount);

	Object_put((struct Object**) conf);
}

/** @} */

/**
* @name Constructor and Destructor
* @{
*/

/**
*  Objects constructor
*  @arg Object that was just allocated
*/
int ProxyConfig_constructor(struct Object *obj)
{
	struct ProxyConfig *config = (struct ProxyConfig *)obj;
	DBG(5, " constructor %p\n", config);
	return 0;
}


/**
*  Objects destructor
*  @arg Object that is going to be free'd
*/
int ProxyConfig_destructor(struct Object *obj)
{
	struct ProxyConfig *conf = (struct ProxyConfig *)obj;
	DBG(5, " destructor %p\n", conf);

	return 0;
}

/** @} */

static struct Object_ops obj_ops = {
	.obj_name           = "ProxyConfig",
	.obj_size           = sizeof(struct ProxyConfig),
	.obj_constructor    = ProxyConfig_constructor,
	.obj_destructor     = ProxyConfig_destructor,
	
};

static struct ProxyConfig* ProxyConfig_alloc(struct Object_ops *ops)
{
	struct ProxyConfig *conf;

	conf = (struct ProxyConfig*) Object_alloc(ops);

	return conf;
}


struct ProxyConfig* ProxyConfig_new(void)
{
	return ProxyConfig_alloc(&obj_ops);
}


//TODO pass XML arg, or filename
int ProxyConfig_loadConfig(struct ProxyConfig* conf, const char *xml)
{	
// 	int ret;

	if (!xml) {
		DBG(1, "Invalid config file\n");
		return -EINVAL;
	}

	return 0;
}

uint16_t ProxyConfig_getHighQNum(struct ProxyConfig* conf) {
	return conf->high_queue_num;
}

uint16_t ProxyConfig_getLowQNum(struct ProxyConfig* conf) {
	return conf->low_queue_num;
}
void ProxyConfig_setHighQNum(struct ProxyConfig* conf,uint16_t num) {
	conf->high_queue_num = num;
}

void ProxyConfig_setLowQNum(struct ProxyConfig* conf,uint16_t num) {
	conf->low_queue_num = num;
}

/** @} */