#include <stdlib.h>
#include <errno.h>

#ifdef HAVE_CONFIG_H
#include "nfq-proxy-config.h"
#endif


#include "Filter.h"
#include "nfq_proxy_private.h"


static struct Filter_ops *get_fobj_ops(struct Filter *fobj)
{
	if (!fobj->fo_ops)
		BUG();
	
	return fobj->fo_ops;
}

#if 0
static struct Object_ops *get_obj_ops(struct Filter *fobj)
{

	if (!fobj->obj_ops)
		BUG();
	
	return fobj->obj_ops;
}
#endif

/**
 * Allocate a new object of kind specified by the operations handle
 * @arg ops		operations handle
 * @return The new object or NULL
 */
struct Filter *Filter_alloc(struct Filter_ops *fo_ops)
{
	struct Filter *new_filter;
	struct Object_ops *obj_ops = fo_ops->ops;

	if (obj_ops->obj_size < sizeof(*new_filter))
		BUG();

	new_filter = (struct Filter *) Object_alloc(obj_ops);
	if (!new_filter)
		return NULL;

	DBG(4, "Allocated new filter object %p\n", new_filter);
	
	new_filter->fo_ops = fo_ops;
	if (fo_ops->foo_constructor) {
		DBG(4, "New filter object %p has constructor\n", new_filter);
		fo_ops->foo_constructor(new_filter);
	}

	return new_filter;
}


void Filter_free(struct Filter **obj_in)
{
	struct Filter *obj; /* just used to de-reference input arg */
	struct Filter_ops *fops;
	if (!obj_in || !*obj_in)
		return;

	obj = *obj_in;
	fops = get_fobj_ops(obj);
	
	
	if (obj->refcount > 0)
		DBG(1, "Warning: Freeing object in use... refcount=%d\n", obj->refcount);

	/* Call this objects desctructor */
	if (fops->foo_destructor)
		fops->foo_destructor(obj);

	DBG(4, "Freed filter object %p\n", obj);
	
	/* call parents destructor */
	Object_free((struct Object**)obj_in);
}

/**
* @name Reference Management
* @{
*/

/**
* Acquire a reference on a object
* @arg obj  	object to acquire reference from
*/
void Filter_get(struct Filter *obj)
{
	obj->refcount++;
	DBG(4, "New reference to filter object %p, total refcount %d\n",
	       obj, obj->refcount);
}

/**
* Release a reference from an object
* @arg obj		object to release reference from
*/
void Filter_put(struct Filter **obj_in)
{
	struct Filter *obj;

	if (!obj_in || !*obj_in)
		return;

 	obj = *obj_in;

	obj->refcount--;
	DBG(4, "Returned object reference %p, %d remaining\n",
		obj, obj->refcount);
	       
	if (obj->refcount < 0)
		BUG();

	if (obj->refcount <= 0)
 		Filter_free(obj_in);
}


bool Filter_shared(struct Filter *obj)
{
	return obj->refcount > 1;
}

int Filter_fromXml(struct Filter *fo, const char *xml)
{
	struct Filter_ops *ops = get_fobj_ops(fo);
	
	if (!ops->foo_load_from_xml) {
		DBG(1, "Invalid object does not have load XML operation\n");
		return -EINVAL;
	}
	DBG(5, "Calling load XML operation\n");
	
	return ops->foo_load_from_xml(fo, xml);
}
