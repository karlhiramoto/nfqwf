
#ifdef HAVE_CONFIG_H
#include "nfq-web-filter-config.h"
#endif

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <libxml/parser.h>
#include <libxml/tree.h>


#include "ProxyConfig.h"
#include "FilterType.h"
#include "FilterList.h"
#include "Rules.h"
#include "ContentFilter.h"
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
	uint16_t low_queue_num;     /**<  Low queue ID*/
	uint16_t high_queue_num;    /**<  High queue ID */
	enum non_http_action non_http_action;
	/** Is anti virus scan active, if true, and content length less
	   than skip size, then save file */
	bool av_active;
	unsigned int av_skip_size;  /**< Only scan files small then skip size */
	char *error_page;           /**<  */
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
	config->cf = ContentFilter_new();
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
	ContentFilter_put(&conf->cf);

	return 0;
}

/** @} */

static struct Object_ops obj_ops = {
	.obj_type           = "ProxyConfig",
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
int ProxyConfig_loadConfig(struct ProxyConfig* conf, const char *config_xml_file)
{	
	int ret;
	xmlDoc *doc = NULL;
	xmlNode *root_node = NULL;
	xmlChar *prop = NULL;
	
	if (!config_xml_file) {
		DBG(1, "Invalid config file\n");
		return -EINVAL;
	}

	DBG(1, "Loading XML Config file '%s'\n", config_xml_file);

	LIBXML_TEST_VERSION
	xmlInitParser();

	/*parse the file and get the DOM */
	doc = xmlReadFile(config_xml_file, NULL, 0);

	if (doc == NULL) {
		ERROR(" could not parse file %s\n", config_xml_file);
		return -1;
	}

	/*Get the root element node */
	root_node = xmlDocGetRootElement(doc);

	DBG(3, "XML root node='%s'\n", root_node->name);

	if (xmlStrcmp(root_node->name, BAD_CAST XML_ROOT_NODE_NAME))
		ERROR_FATAL("XML root node name '%s' != '%s'\n" ,
			root_node->name,	XML_ROOT_NODE_NAME);

	// set default
	conf->non_http_action = non_http_action_reset;
	prop = xmlGetProp(root_node, BAD_CAST "non_http_action");
	if (prop) {
		if (!strncasecmp((const char*) prop, "reset", 6)) {
			conf->non_http_action = non_http_action_reset;
		} else if (!strncasecmp((const char*) prop, "accept", 6)) {
			conf->non_http_action = non_http_action_accept;
		} else if (!strncasecmp((const char*) prop, "drop", 5)) {
			conf->non_http_action = non_http_action_drop;
		} else {
			WARN(" invalid 'non_http_action' XML prop. using default \n");
		}
		xmlFree(prop);
	}

	ret = ContentFilter_loadConfig(conf->cf, root_node->children);
	if (ret) {
		DBG(1, "Error loading filter config");
	}

	/*free the document */
	xmlFreeDoc(doc);

	/*
	*Free the global variables that may
	*have been allocated by the parser.
	*/
	xmlCleanupParser();

	return 0;
}

//TODO  think about making this and other one liners a static inline in the .h 
struct ContentFilter * ProxyConfig_getContentFilter(struct ProxyConfig* conf)
{
 	if (!conf) {
		ERROR_FATAL("Invalid config obj\n");
		return NULL;
	}
	return conf->cf;
}

uint16_t ProxyConfig_getHighQNum(struct ProxyConfig* conf) {
	return conf->high_queue_num;
}

uint16_t ProxyConfig_getLowQNum(struct ProxyConfig* conf) {
	return conf->low_queue_num;
}
void ProxyConfig_setHighQNum(struct ProxyConfig* conf, uint16_t num) {
	conf->high_queue_num = num;
}

void ProxyConfig_setLowQNum(struct ProxyConfig* conf, uint16_t num) {
	conf->low_queue_num = num;
}

#if 0
void ProxyConfig_setNonHttpAction(struct ProxyConfig* conf, enum non_http_action action) {
	conf->non_http_action = action;
}
#endif

enum non_http_action ProxyConfig_getNonHttpAction(struct ProxyConfig* conf) {
	return conf->non_http_action;
}

/** @} */

