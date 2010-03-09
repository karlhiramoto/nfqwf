#include <stdlib.h>

#ifdef HAVE_CONFIG_H
#include "nfq-proxy-config.h"
#endif

#include "Object.h"
#include "nfq_proxy_private.h"

/// Object ID sequence.  NOTE  object allocation for now only done by one thread so no mutex needed yet. 
static unsigned int id_seq = 0;

static struct Object_ops *fobj_ops(struct Object *obj)
{
	if (!obj->obj_ops)
		BUG();
	
	return obj->obj_ops;
}

/**
* Allocate a new object of kind specified by the operations handle
* @arg ops		operations handle
* @return The new object or NULL
*/
struct Object *Object_alloc(struct Object_ops *ops)
{
	struct Object *new_obj;
	
	if (ops->obj_size < sizeof(struct Object))
		BUG();
	
	new_obj = calloc(1, ops->obj_size);
	if (!new_obj)
		return NULL;
	
	new_obj->id = id_seq++;
	
	new_obj->refcount = 1;
	
	new_obj->obj_ops = ops;
	if (ops->obj_constructor)
		ops->obj_constructor(new_obj);
	
	DBG(4, "Allocated new object %p\n", new_obj);
	
	return new_obj;
}


void Object_free(struct Object *obj)
{
	struct Object_ops *ops = fobj_ops(obj);

	if (obj->refcount > 0)
		DBG(1, "Warning: Freeing object in use...\n");

	if (ops->obj_destructor)
		ops->obj_destructor(obj);

	free(obj);

	DBG(4, "Freed object %p\n", obj);
}

/**
* @name Reference Management
* @{
*/

/**
* Acquire a reference on a object
* @arg obj  	object to acquire reference from
*/
void Object_get(struct Object *obj)
{
	obj->refcount++;
	DBG(4, "New reference to object %p, total refcount %d\n",
		obj, obj->refcount);
}

/**
* Release a reference from an object
* @arg obj		object to release reference from
*/
void Object_put(struct Object *obj)
{
	if (!obj)
		return;
	
	obj->refcount--;
	DBG(4, "Returned object reference %p, %d remaining\n",
		obj, obj->refcount);
		
		if (obj->refcount < 0)
			BUG();
		
		if (obj->refcount <= 0)
			Object_free(obj);
}

/**
* Check whether this object is used by multiple users
* @arg obj		object to check
* @return true or false
*/
bool Object_shared(struct Object *obj)
{
	return obj->refcount > 1;
}

