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

#ifdef HAVE_CONFIG_H
#include "nfq-web-filter-config.h"
#endif

#define _GNU_SOURCE

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <libxml/parser.h>
#include <libxml/tree.h>


#include "WfConfig.h"
#include "ContentFilter.h"
#include "nfq_wf_private.h"

/**
* @ingroup Object
* @defgroup WfConfig WfConfig. Main configuration object
* @{
*/


struct WfConfig
{
	/** Base objects member variables */
	OBJECT_COMMON;

	/** We will use the queue range from low to high.
	See "man iptables" --queue-balance */
	uint16_t low_queue_num;     /**<  Low queue ID*/
	uint16_t high_queue_num;    /**<  High queue ID */
	enum non_http_action non_http_action;
	/** Is anti virus scan active, only up to max file filter size may
		be scanned otherwise skip file scan */
	unsigned int max_filtered_file_size;

	/** Maximum out of order packets
		Out of order packets are buffered for later analysis,
		On systems with low amounts of RAM,
		memory usage needs to be controlled to avoid OOM killer.

		The worst case scenario is a long fat connection (high bandwidth high ping time)
		a large file, and large TCP window.
	*/
	unsigned int pkt_buf_size;

	char *tmp_dir; /* where to store tmp files if AV file scan active */

	/// TODO a configurable error page.
	char *error_page;
	struct ContentFilter *cf; /* content filter object */
};

/**
* @name Reference Management
* @{
*/

/** Get a reference counter */
void WfConfig_get(struct WfConfig *conf) {
	Object_get((struct Object*) conf);
	DBG(4, "New reference to WfConfig %p refcount = %d\n",
		conf, conf->refcount);
}

/** Release reference counter */
void WfConfig_put(struct WfConfig **conf) {

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
int WfConfig_constructor(struct Object *obj)
{
	struct WfConfig *config = (struct WfConfig *)obj;
	DBG(5, " constructor %p\n", config);
	config->cf = ContentFilter_new();
	return 0;
}


/**
*  Objects destructor
*  @arg Object that is going to be free'd
*/
int WfConfig_destructor(struct Object *obj)
{
	struct WfConfig *conf = (struct WfConfig *)obj;
	DBG(5, " destructor %p\n", conf);
	ContentFilter_put(&conf->cf);

	if (conf->tmp_dir)
		free(conf->tmp_dir);

	return 0;
}

/** @} */

static struct Object_ops obj_ops = {
	.obj_type           = "WfConfig",
	.obj_size           = sizeof(struct WfConfig),
	.obj_constructor    = WfConfig_constructor,
	.obj_destructor     = WfConfig_destructor,

};

static struct WfConfig* WfConfig_alloc(struct Object_ops *ops)
{
	struct WfConfig *conf;

	conf = (struct WfConfig*) Object_alloc(ops);

	return conf;
}


struct WfConfig* WfConfig_new(void)
{
	return WfConfig_alloc(&obj_ops);
}


//TODO pass XML arg, or filename
int WfConfig_loadConfig(struct WfConfig* conf, const char *config_xml_file)
{
	int ret;
	xmlDoc *doc = NULL;
	xmlNode *root_node = NULL;
	xmlChar *prop = NULL;
	struct stat tmp_dir_stat;
	char *cmd;

	if (!config_xml_file) {
		ERROR("Invalid config file\n");
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
	conf->non_http_action = non_http_action_accept;
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
	prop = xmlGetProp(root_node, BAD_CAST "max_filtered_file_size");
	if (prop) {
		conf->max_filtered_file_size = atoi((const char*)prop);
		xmlFree(prop);
	} else {
		conf->max_filtered_file_size = 1024*1024;
	}

	prop = xmlGetProp(root_node, BAD_CAST "pkt_buf_size");
	if (prop) {
		conf->pkt_buf_size = atoi((const char*)prop);
		xmlFree(prop);
		if (conf->pkt_buf_size < 10) {
			WARN(" invalid 'pkt_buf_size' XML prop. using default \n");
			conf->pkt_buf_size = 2048;
		}
	} else {
		conf->pkt_buf_size = 2048;
	}
	prop = xmlGetProp(root_node, BAD_CAST "tmp_dir");
	if (prop) {
		conf->tmp_dir = strdup((const char*)prop);
		xmlFree(prop);
	} else {
		conf->tmp_dir = strdup("/tmp");
	}
	ret = stat(conf->tmp_dir, &tmp_dir_stat);
	if (ret) {
		DBG(1, "tmp dir '%s' may not exist trying to create\n", conf->tmp_dir);
		ret = asprintf(&cmd, "mkdir -p %s", conf->tmp_dir);
		if (ret == -1) {
			ERROR("asprintf for dir '%s' \n", conf->tmp_dir);
		} else {
			ret = system(cmd);
			if (ret) {
				ERROR("trying to create dir '%s' err=%d=%m\n", cmd, errno);
			}
		}

		if (cmd)
			free(cmd);

		ret = stat(conf->tmp_dir, &tmp_dir_stat);
		if (ret == -1) {
			ERROR("checking tmp dir '%s' err=%d=%m\n", conf->tmp_dir, errno);
		}
	}

	DBG(1, "max file filter=%d  tmp_dir='%s'\n",
		conf->max_filtered_file_size, conf->tmp_dir);
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
struct ContentFilter * WfConfig_getContentFilter(struct WfConfig* conf)
{
 	if (!conf) {
		ERROR_FATAL("Invalid config obj\n");
		return NULL;
	}
	return conf->cf;
}

uint16_t WfConfig_getHighQNum(struct WfConfig* conf) {
	return conf->high_queue_num;
}

uint16_t WfConfig_getLowQNum(struct WfConfig* conf) {
	return conf->low_queue_num;
}
void WfConfig_setHighQNum(struct WfConfig* conf, uint16_t num) {
	conf->high_queue_num = num;
}

void WfConfig_setLowQNum(struct WfConfig* conf, uint16_t num) {
	conf->low_queue_num = num;
}

unsigned int WfConfig_getMaxFiltredFileSize(struct WfConfig* conf) {
	return conf->max_filtered_file_size;
}

unsigned int WfConfig_getPktBuffSize(struct WfConfig* conf)
{
	return conf->pkt_buf_size;
}


#if 0
void WfConfig_setNonHttpAction(struct WfConfig* conf, enum non_http_action action) {
	conf->non_http_action = action;
}
#endif

enum non_http_action WfConfig_getNonHttpAction(struct WfConfig* conf) {
	return conf->non_http_action;
}

const char *WfConfig_getTmpDir(struct WfConfig* conf) {
	return conf->tmp_dir;
}

/** @} */

