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

#ifndef OBJECT_H
#define OBJECT_H

#ifdef HAVE_CONFIG_H
#include "nfq-web-filter-config.h"
#endif

#include <stdbool.h>

/**
* @defgroup Object Object.  A Generic object that others may inherit.
* @{
*/

/**
* Common Object Header
*
* This macro must be included as first member in every object,
* that inherits this object
* @var id    Object ID
* @var refcount  Counter for number of holders of this object
*/
#define OBJECT_COMMON \
int id; \
int refcount; \
struct Object_ops *obj_ops;

/**
* @struct Object
* @brief This is a base object that all other object will inherit
* it features a unique ID per object and reference counters
*/
struct Object
{
	/** Base class members */
	OBJECT_COMMON;
};


/**
* @struct Object_ops
* @brief Object operations, defines various Object properties and callbacks.
*/
struct Object_ops
{
	/** Unique type name of the object */
	char * obj_type;

	/** Size of object */
	size_t obj_size;

	/**
	* Optional callback to init/allocate any private data
	*/
	int (*obj_constructor)(struct Object *);

	/**
	* Optional callback to free any private data
	*/
	int (*obj_destructor)(struct Object *);

	/*optional callback to clone private data */
	int (*obj_clone)(struct Object *dst, struct Object *src);

	/** optional callback to compare two objects
	 @return 0 if equal. -1, 1 see man qsort()
	*/
	int (*obj_compare)(struct Object *dst, struct Object *src);

};

struct Object *Object_alloc(struct Object_ops *ops);

void Object_free(struct Object **obj);

/**
* @name Reference Management
* @{
*/

/**
* Release a reference from an object.
* When reference count reaches 0 free and will NULL pointer
* @arg obj	object to release reference from
*/
void Object_put(struct Object **obj);

/**
* Acquire a reference on a object
* @arg obj  	object to acquire reference from
*/
void Object_get(struct Object *obj);

/**
* Check whether this object is used by multiple users
* @arg obj		object to check
* @return true or false
*/
bool Object_shared(struct Object *obj);

/** @}
end of refrence management
*/



/** @}
end of Object file
*/


#endif

