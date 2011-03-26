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

#include <stdlib.h>

#ifdef HAVE_CONFIG_H
#include "nfq-web-filter-config.h"
#endif

#include "Object.h"
#include "nfq_wf_private.h"

/// Object ID sequence.  NOTE  object allocation for now only done by one thread so no mutex needed yet.
static unsigned int id_seq = 0;

static struct Object_ops *get_obj_ops(struct Object *obj)
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

	DBG(4, "Allocated new object %p name='%s'\n", new_obj, ops->obj_type);

	return new_obj;
}

/**
* free an object
* @brief call object destructor.
* @brief Note this should only be called from Object_put() or an inherited _put()
* @arg obj  pointer to pointer to object so we can return NULL pointer of free'd memory
*/
void Object_free(struct Object **obj)
{
	struct Object_ops *ops = get_obj_ops(*obj);

	if ((*obj)->refcount > 0)
		DBG(1, "Warning: Freeing object in use... name='%s'\n", ops->obj_type);

	if (ops->obj_destructor)
		ops->obj_destructor(*obj);

	DBG(4, "Free object %p name='%s'\n", *obj, ops->obj_type);

	free(*obj);
	*obj = NULL;
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
void Object_put(struct Object **obj_arg)
{
	struct Object *obj;
	if (!*obj_arg)
		return;

	obj = *obj_arg; // derefernce only once

	obj->refcount--;
	DBG(4, "Returned object reference %p, %d remaining\n",
		obj, obj->refcount);

	if (obj->refcount < 0)
		BUG();

	if (obj->refcount <= 0)
		Object_free(obj_arg);

	*obj_arg = NULL;
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

