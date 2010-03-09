#include <stdlib.h>
#include <errno.h>
#include <string.h>

#ifdef HAVE_CONFIG_H
#include "nfq-proxy-config.h"
#endif

#include "ContentFilter.h"
#include "FilterType.h"
#include "FilterList.h"
#include "Rules.h"
#include "nfq_proxy_private.h"

void ContentFilter_get(struct ContentFilter **cf) {
	(*cf)->refcount++;
	DBG(4, "New reference to Rule list %p refcount = %d\n",
		*cf, (*cf)->refcount);
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
	cf->Object_list = FilterList_new();

	DBG(5, " constructor obj_list=%p\n", cf->Object_list);
	return 0;
}

int ContentFilter_destructor(struct Object *obj)
{
	struct ContentFilter *cf = (struct ContentFilter *)obj;
	DBG(5, " destructor\n");
	FilterList_free(&(cf->Object_list));
	return 0;
}


static struct Object_ops obj_ops = {
	.obj_name           = "ContentFilter",
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
int ContentFilter_addFilterObj(struct ContentFilter* cf, struct Filter *fo)
{
	if (!fo) {
		DBG(1, "Invalid object to add\n");
		return -EINVAL;
	}

	FilterList_addTail(cf->Object_list, fo);
	return 0;
}

//TODO pass XML arg, or filename
int ContentFilter_loadConfig(struct ContentFilter* cf, const char *xml)
{
	struct Filter *fo = NULL;

	int ret;

	if (!xml) {
		DBG(1, "Invalid config file\n");
		return -EINVAL;
	}

	// TODO FIXME  load config file here
	
	
	// TODO  for each object type in config file, load it into object list
	{
		fo = FilterType_get_new("filter/ip");
		if (!fo) {
			DBG(1, "Object not found\n");
		} else {
			ret = ContentFilter_addFilterObj(cf, fo);
			ret = Filter_fromXml(fo, "69.163.204.248");
		}
	}
	
	// TODO  for each Rule link it to the ojects
	
	return 0;
}
