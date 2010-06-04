#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include "nfq_proxy_private.h" // debug macros
#include "Filter.h"
#include "FilterType.h"


/**
* @ingroup Object
* @defgroup FilterType FilterType.  A lists of available filter types. 
* @{
*/


//list of available filters
static struct Filter_ops **FilterType_list = NULL;
static unsigned int FilterType_list_count = 0;


/** @brief search for a filter type in the filter list */
static struct Filter_ops* FilterType_list_search(const char *name)
{
	int i;

	for (i = 0; FilterType_list && FilterType_list[i]; i++) {
		if (!strcmp(name, FilterType_list[i]->ops->obj_type)) {
			return FilterType_list[i];
		}
	}
	return NULL;
}

/** @brief regiter a filter type to the filter list */
int FilterType_register(struct Filter_ops *fo_ops)
{
	const char *name;
	if (!fo_ops || !fo_ops->ops->obj_type || !fo_ops->ops->obj_type[0]) {
		DBG(1, "Invalid filter name\n");
		return -EINVAL;
	}
	name = fo_ops->ops->obj_type;
	if(FilterType_list_search(name)) {
		DBG(1, "Invalid duplicate filter '%s'\n", name);
	}

	FilterType_list  = realloc(FilterType_list, (sizeof (struct Filter_ops *) *(FilterType_list_count+2)));
	if (!FilterType_list)
		return -ENOMEM;
	
	FilterType_list[FilterType_list_count] =  fo_ops;

	DBG(5, "Registered new filter '%s'\n", name);

	FilterType_list_count++;
	FilterType_list[FilterType_list_count] = NULL; /* NULL term */

	return 0;
}


void __exit FilterType_cleanup(void)
{
	FilterType_list = realloc(FilterType_list, 0);
}

struct Filter *FilterType_get_new(const char *name)
{
   struct Filter *fo = NULL;
   struct Filter_ops *fo_ops = NULL;
   
   fo_ops = FilterType_list_search(name);
   if (!fo_ops) {
	   ERROR("No filter object of type '%s' found\n", name);
	   return NULL;
   }
 
   fo = Filter_alloc(fo_ops);

   DBG(5, "new filter = %p id=%d\n", fo, fo->id);
   return fo;
}

/**
* @}
*/

