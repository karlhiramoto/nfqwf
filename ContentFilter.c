#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <syslog.h>

#ifdef HAVE_CONFIG_H
#include "nfq-web-filter-config.h"
#endif


#include "ContentFilter.h"
#include "FilterType.h"
#include "FilterList.h"
#include "Rules.h"
#include "HttpReq.h"
#include "HttpConn.h"
#include "nfq_proxy_private.h"

/**
* Content filter object.
* Every HTTP new connection will have a reference to this object.
* When HTTP connection ends reference to this object will be removed.
* If ContentFilter configuration changes, new ContentFilter object allocated,
* New connections get new object.  Old connections keep old object, when
* all references to old ContentFilter object removed, the object gets deleted.
*/
struct ContentFilter
{
	OBJECT_COMMON
	enum Action default_action;
	unsigned int rule_list_count; /** number of rules */
	struct Rule **rule_list;   /** list of rules that contain objects */
	struct FilterList *obj_list; /** List of objects used */
	bool has_stream_filter;
	bool has_file_filter;
};

void ContentFilter_get(struct ContentFilter *cf) {
	cf->refcount++;
	DBG(4, "New reference to Rule list %p refcount = %d\n",
		cf, cf->refcount);
}

void ContentFilter_put(struct ContentFilter **cf) {

	DBG(4, "removing CF reference to %p refcount = %d\n",
		*cf, (*cf)->refcount);
	
	Object_put((struct Object**)cf);
}

int ContentFilter_constructor(struct Object *obj)
{
	struct ContentFilter *cf = (struct ContentFilter *)obj;
	DBG(5, " constructor\n");
	cf->default_action = Action_accept; /* override this when we load config */
	cf->obj_list = FilterList_new();

	cf->rule_list = calloc(1, sizeof(struct Rule *) * 2);
	DBG(5, " constructor obj_list=%p\n", cf->obj_list);

	return 0;
}

int ContentFilter_destructor(struct Object *obj)
{
	struct ContentFilter *cf = (struct ContentFilter *)obj;
	int i;

	DBG(5, " destructor\n");

	for (i = 0; i < cf->rule_list_count; i++) {
		DBG(5, " Free rule %d\n", i);
		if (cf->rule_list[i])
			Rule_del(&cf->rule_list[i]);
	}
	free(cf->rule_list);
	DBG(5, " Free FilterList objects\n");
	FilterList_del(&(cf->obj_list));
	
	return 0;
}


static struct Object_ops obj_ops = {
	.obj_type           = "ContentFilter",
	.obj_size           = sizeof(struct ContentFilter),
	.obj_constructor    = ContentFilter_constructor,
	.obj_destructor     = ContentFilter_destructor,

};

static struct ContentFilter* ContentFilter_alloc(struct Object_ops *ops)
{
	struct ContentFilter *cf;

	cf = (struct ContentFilter*) Object_alloc(ops);

	return cf;
}


struct ContentFilter* ContentFilter_new(void)
{
	return ContentFilter_alloc(&obj_ops);
}


/** @brief add the filter to the list of objects */
static int ContentFilter_addFilterObj(struct ContentFilter* cf, struct Filter *fo)
{
	if (!fo) {
		DBG(1, "Invalid object to add\n");
		return -EINVAL;
	}

	FilterList_addTail(cf->obj_list, fo);
	return 0;
}
static void ContentFilter_addRule(struct ContentFilter* cf, struct Rule *rule)
{
	cf->rule_list = realloc(cf->rule_list, (cf->rule_list_count+2) * sizeof(struct Rule*));
	if (!cf->rule_list)
		ERROR_FATAL("realoc error. nomem\n");

	cf->rule_list[cf->rule_list_count] = rule;
	cf->rule_list_count++;
	cf->rule_list[cf->rule_list_count] = NULL;
}

static int ContentFilter_loadRuleNode(struct ContentFilter* cf, xmlNode *rule_node)
{
	struct Filter *fo = NULL;
	struct Rule *rule;
	xmlChar *prop = NULL;
	int ret = 0;
	int id = 0;
	int log = 0;
	enum Action action = Action_nomatch;
	char buffer[32];
	xmlNode *filter_node;
	int group;
	
	if (!rule_node)
		return -EINVAL;

	prop = xmlGetProp(rule_node, BAD_CAST RULE_ID_XML_PROP);
	if (!prop) {
		return -ENOENT;
	}

	ret = sscanf((char *) prop, "%d", &id);
	if (ret < 1) {
		ERROR(" Parsing %s\n", RULE_ID_XML_PROP);
	}
	xmlFree(prop);


	prop = xmlGetProp(rule_node, BAD_CAST "action");
	if (!prop) {
		ERROR("Rule missing 'action'\n");
		return -ENOENT;
	}
	action = Action_fromAscii((char *) prop);
	xmlFree(prop);

	prop = xmlGetProp(rule_node, BAD_CAST "log");
	if (!prop) {
		log = 0;
	} else  {
		ret = sscanf((char *) prop, "%d", &log);
		if (ret < 1) {
			ERROR(" Parsing %s\n", RULE_ID_XML_PROP);
		}
		xmlFree(prop);
	}
	
	rule = Rule_new();
	rule->log = log;
	Rule_setId(rule, id);
	Rule_setAction(rule, action);


	prop = xmlGetProp(rule_node, BAD_CAST "comment");
	if (prop) {
		Rule_setComment(rule, (char *)prop);
		xmlFree(prop);
	}
	
	DBG(1, "Rule ID=%d action=%s log=%d comment='%s'\n", id,
		Action_toAscii(action, buffer, sizeof(buffer)), log,
		Rule_getComment(rule));

	// for each filter
	for (filter_node = rule_node->children ; filter_node ;
			filter_node = filter_node->next ) {

		if (filter_node->type != XML_ELEMENT_NODE)
			continue;

		prop = xmlGetProp(filter_node, BAD_CAST FILTER_ID_XML_PROP);
		if (!prop) {
			ERROR(" '%s' %d  Filter has no '%s'\n",
				  filter_node->name,
				  Rule_getId(rule), FILTER_ID_XML_PROP);
			continue;
		}
		
		ret = sscanf((char *) prop, "%d", &id);
		if (ret < 1) {
			ERROR(" Parsing %s in rule %d\n",
				FILTER_ID_XML_PROP, Rule_getId(rule));
			xmlFree(prop);
			continue;
		}
		xmlFree(prop);

		prop = xmlGetProp(filter_node, BAD_CAST GROUP_XML_PROP);
		if (!prop) {
			ERROR(" rule %d  Filter_ID=%d has no '%s'\n",
				  Rule_getId(rule), id, GROUP_XML_PROP);
				  continue;
		}
		ret = sscanf((char *) prop, "%d", &group);
		if (ret < 1) {
			ERROR(" Parsing %s in rule %d\n",
				  GROUP_XML_PROP, Rule_getId(rule));
				  xmlFree(prop);
				  continue;
		}
		xmlFree(prop);
		if (group >= MAX_FITER_GROUPS) {
			ERROR("group ID must be 0-%d\n", MAX_FITER_GROUPS-1);
			continue;
		}

		fo = FilterList_searchFilterId(cf->obj_list, id);
		if (!fo) {
			ERROR("Filter ID=%d not found.\n", id);
			continue;
		}
		DBG(1, "Rule_ID=%d Filter_ID=%d, group=%d\n",
			Rule_getId(rule), id, group);

		Rule_addFilter(rule, group, fo);

	}

	ContentFilter_addRule(cf, rule);

	return 0;
}
static int ContentFilter_loadRulesConfig(struct ContentFilter* cf, xmlNode *start_node)
{
	xmlNode *cur_node = NULL;

	if (!start_node) {
		ERROR_FATAL( "Invalid XML config\n");
		return -EINVAL;
	}

	// for each rule node
	for (cur_node = start_node; cur_node; cur_node = cur_node->next) {
		if (cur_node->type == XML_ELEMENT_NODE) {
			DBG(2, "    node type: Element, name: %s\n", cur_node->name);
			if (xmlStrcmp(cur_node->name, BAD_CAST "Rule")) {
				ERROR_FATAL("Should only have 'Rule' nodes inside 'Rules' cur node='%s'\n",
					cur_node->name);
			}
			ContentFilter_loadRuleNode(cf, cur_node);
		}
	}
	return 0;
}

static int ContentFilter_loadFilterObjsConfig(struct ContentFilter* cf, xmlNode *start_node)
{
	xmlNode *cur_node = NULL;
	int filter_count = 0;
	struct Filter *fo = NULL;
	xmlChar *prop = NULL;
	int ret = 0;

	if (!start_node) {
		DBG(1, "No filter objects defined\n");
		return 0;
	}

	for (cur_node = start_node; cur_node; cur_node = cur_node->next) {
		if (cur_node->type == XML_ELEMENT_NODE) {
			DBG(2, "    node type: Element, name: %s\n", cur_node->name);

			if (xmlStrcmp(cur_node->name, BAD_CAST "FilterObject")) {
				ERROR_FATAL("Should only have 'FilterObject' inside 'FilterObjectsDef' cur node='%s'\n",
					cur_node->name);
			}

			prop = xmlGetProp(cur_node, BAD_CAST "type");
			if (prop) {
				DBG(3, "Filter Object type = '%s'\n", (char *) prop);
				fo = FilterType_get_new((const char *) prop);

				if (!fo) {
					WARN(" No filter object of type '%s'\n", (const char *) prop);
					xmlFree(prop);
					continue;
				}
				ret = Filter_fromXml(fo, cur_node);
				if (ret) {
					WARN(" loading %s\n", (const char *) prop);
				}
				ret = ContentFilter_addFilterObj(cf, fo);
				if (ret) {
					DBG(1, "Error adding filter object to list\n");
				} else {
					// Now in filter list, release our ref
					Filter_put(&fo);
				}
				xmlFree(prop);
			}
			prop = NULL;
			filter_count++;
		}
	}
	return filter_count;
}

static int __has_stream_filter_cb(struct Filter *fo, void *data)
{
	if (fo->fo_ops->foo_stream_filter)
		return 1;

	return 0;
}

static void check_for_stream_filter(struct ContentFilter* cf)
{
	int rc = 0;
	rc = FilterList_foreach(cf->obj_list, NULL, __has_stream_filter_cb);
	if (rc)
		cf->has_stream_filter = true;

}

static int __has_file_filter_cb(struct Filter *fo, void *data)
{
	if (fo->fo_ops->foo_file_filter)
		return 1;

	return 0;
}

static void check_for_file_filter(struct ContentFilter* cf)
{
	int rc = 0;
	rc = FilterList_foreach(cf->obj_list, NULL, __has_file_filter_cb);
	if (rc)
		cf->has_file_filter = true;
}


int ContentFilter_loadConfig(struct ContentFilter* cf, xmlNode *start_node)
{
	xmlNode *cur_node = NULL;
	int ret;

	if (!start_node) {
		ERROR_FATAL("Invalid XML config\n");
		return -EINVAL;
	}

	for (cur_node = start_node; cur_node; cur_node = cur_node->next) {
		if (cur_node->type == XML_ELEMENT_NODE) {
			DBG(2, "  node type: Element, name: %s\n", cur_node->name);
			if (!xmlStrcmp(cur_node->name, BAD_CAST "FilterObjectsDef")) {
				ret = ContentFilter_loadFilterObjsConfig(cf, cur_node->children);
				if (ret < 0) {
					ERROR_FATAL("Error parsing xml filter objects\n");
				}
				DBG(1, "Read %d filter objects from XML config\n", ret);
			} else if (!xmlStrcmp(cur_node->name, BAD_CAST "Rules")) {
				ret = ContentFilter_loadRulesConfig(cf, cur_node->children);
				if (ret < 0) {
					ERROR_FATAL("Error parsing xml rules\n");
				}
			}
		}
	}
	check_for_file_filter(cf);
	check_for_stream_filter(cf);
	return 0;
}

static int start_req_cb(struct Filter *fo, void *data)
{
	struct HttpReq *req = (struct HttpReq *) data;

	if (fo->fo_ops->foo_request_start)
		return fo->fo_ops->foo_request_start(fo, req);

	return 0;
}

int ContentFilter_requestStart(struct ContentFilter* cf, struct HttpReq *req)
{
	DBG(5, "Starting\n");

	FilterList_foreach(cf->obj_list, req, start_req_cb);
	return 0;
}

/**
* @brief Log the request
* @todo Think about making log plugin modules that we register like the filters
**/
static void __ContentFilter_logReq(struct ContentFilter* cf, struct HttpReq *req, struct Rule *rule)
{
	//TODO for each log plugin.  Call log.
	syslog(LOG_INFO, "Proxy matched rule id=%d url='%s' verdict=%d length=%llu",
		   req->rule_matched, req->url, req->verdict, req->server_resp_msg.content_length);
		   
}

int ContentFilter_getRequestVerdict(struct ContentFilter* cf, struct HttpReq *req)
{
	struct Rule *rule;
	int i;

	/* for each rule */
	for (i = 0; i < cf->rule_list_count; i++) {
		rule = cf->rule_list[i];
		if (!rule)
			ERROR_FATAL("Bug invalid rule list\n");

		req->verdict = Rule_getVerdict(rule, req);

		if (req->verdict != Action_nomatch) {
			req->rule_matched = Rule_getId(rule);

			// if we should send a log message.
			if (rule->log  || rule->notify)
				__ContentFilter_logReq(cf, req, rule);

			/* match found, return verdict */
			return req->verdict;
		}
	}
	/* no rule  match return default */
	return cf->default_action;
}

struct stream_cb_args {
	const unsigned char *data_stream;
	unsigned int length;
	struct HttpReq *req;
};

static int stream_filter_cb(struct Filter *fo, void *data)
{
	struct stream_cb_args *args;

	if (fo->fo_ops->foo_stream_filter) {
		args = (struct stream_cb_args *) data;
		return fo->fo_ops->foo_stream_filter(fo, args->req,
				args->data_stream, args->length);
	}
	
	return 0;
}

int ContentFilter_filterStream(struct ContentFilter* cf, struct HttpReq *req,
	const unsigned char *data_stream, unsigned int length)
{
	int rc = 0;
	struct stream_cb_args args;

	args.data_stream = data_stream;
	args.length = length;
	args.req = req;

	DBG(5, "Starting length=%d\n", length);

	if (cf->has_stream_filter) {
		rc = FilterList_foreach(cf->obj_list, &args, stream_filter_cb);
		if (rc != Action_nomatch)
			return rc;
	}

	if (cf->has_file_filter) {

	}
	
	return rc;
}


static int file_filter_cb(struct Filter *fo, void *data)
{
	struct HttpReq *req;

	if (fo->fo_ops->foo_file_filter) {
		req = (struct HttpReq *) data;
		return fo->fo_ops->foo_file_filter(fo, req);
	}
	
	return 0;
}


int ContentFilter_fileScan(struct ContentFilter* cf, struct HttpReq *req)
{
	int rc = 0;

	if (cf->has_file_filter) {
		rc = FilterList_foreach(cf->obj_list, req, file_filter_cb);
	}

	return rc;
}

bool ContentFilter_hasFileFilter(struct ContentFilter* cf)
{
	return cf->has_file_filter;
}

