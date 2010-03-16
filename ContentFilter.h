#ifndef CONTENT_FILTER_H
#define CONTENT_FILTER_H 1

#ifdef HAVE_CONFIG_H
#include "nfq-proxy-config.h"
#endif

#include <stdbool.h>
#include "Filter.h"
#include "Rules.h"

/**
* @ingroup Object
* @defgroup ContentFilter Content Filter.  Combine rules and filter objets
* @{
*/

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
	enum Rule_action default_action;
	unsigned int rule_list_count; /** number of rules */
	struct Rule **rule_list;   /** list of rules that contain objects */
	struct FilterList *Object_list; /** List of objects used */
};

void ContentFilter_get(struct ContentFilter **cf);

void ContentFilter_put(struct ContentFilter **cf);

struct ContentFilter* ContentFilter_new(void);


int ContentFilter_loadConfig(struct ContentFilter* cf, const char *xml);

/** @} */
#endif
