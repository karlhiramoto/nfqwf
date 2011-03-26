#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <dlfcn.h>

#include "nfq_wf_private.h" // debug macros
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

static unsigned int library_path_count = 0;
static char **library_path_list = NULL;


void FilterType_addLibPath(const char *path)
{
	if (!path)
		return;

	library_path_list = realloc(library_path_list, (sizeof(char *) * (library_path_count+2)));

	library_path_list[library_path_count] = strdup(path);
	DBG(1, "add plugin path %s\n", library_path_list[library_path_count]);
	library_path_count++;
	library_path_list[library_path_count] = NULL;
}
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

static void search_plugin(const char *name)
{
	char pathname[128];
	char *slash;
	void *handle;
	int i;

	// for each library path specified
	for (i = 0; i < library_path_count; i++) {
		snprintf(pathname, sizeof(pathname), "%s/%s.so", library_path_list[i], name);
		handle = dlopen(pathname, RTLD_NOW | RTLD_LOCAL);
		if (handle) {
			// found
			return;
		}
		DBG(2, "Error opening %s  error='%s'\n", pathname, dlerror());
		slash = strchr(name,'/');
		if (slash) {
			/* try loading plugin without filter/ prefix */
			snprintf(pathname, sizeof(pathname), "%s%s.so", library_path_list[i], slash);
			handle = dlopen(pathname, RTLD_NOW | RTLD_LOCAL);
			if (handle) {
				// found
				return;
			}
			DBG(2, "Error opening %s  error='%s'\n", pathname, dlerror());
		}
	}
	snprintf(pathname, sizeof(pathname), "%s/%s.so", DATADIR, name);
	DBG(2, "Search for pluin in DATADIR='%s' path=%s\n", DATADIR, pathname);
	handle = dlopen(pathname, RTLD_NOW | RTLD_LOCAL);
	if (!handle) {
		DBG(2, "Error opening %s  error='%s'\n", pathname, dlerror());

		ERROR("filter plugin '%s' could not be found in lib path\n", name);
	}

	return;
}

struct Filter *FilterType_get_new(const char *name)
{
	struct Filter *fo = NULL;
	struct Filter_ops *fo_ops = NULL;

	fo_ops = FilterType_list_search(name);
	if (!fo_ops) {
		search_plugin(name);
		fo_ops = FilterType_list_search(name);
	}
	if (!fo_ops) {
		ERROR("No filter object of type '%s' found\n", name);
		return NULL;
	}

	fo = Filter_alloc(fo_ops);

	DBG(5, "new filter = %p id=%d\n", fo, fo->id);
	return fo;
}

void __exit FilterType_cleanup(void)
{
	int i;

	for (i = 0; i < library_path_count; i++) {
		free(library_path_list[i]);
	}
	free(library_path_list);
	FilterType_list = realloc(FilterType_list, 0);
}

/**
* @}
*/

