#ifndef CONTENT_FILTER_H
#define CONTENT_FILTER_H 1

#ifdef HAVE_CONFIG_H
#include "nfq-proxy-config.h"
#endif

#include <stdbool.h>
#include <linux/in.h>
#include "Filter.h"

/**
* @ingroup Object
* @defgroup ContentFilter Content Filter.  Combine rules and filter objets
* @{
*/

struct ContentFilter
{
	OBJECT_COMMON
	unsigned int Rule_list_count; /** number of rules */
	struct Rule **Rule_list;   /** list of rules that contain objects */
	struct FilterList *Object_list; /** List of objects used */
};

void ContentFilter_get(struct ContentFilter **cf);

void ContentFilter_put(struct ContentFilter **cf);

struct ContentFilter* ContentFilter_new(void);


int ContentFilter_loadConfig(struct ContentFilter* cf, const char *xml);

/** @}
end of file
*/
#endif