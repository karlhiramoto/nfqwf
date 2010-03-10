#ifndef OBJECT_H
#define OBJECT_H

#ifdef HAVE_CONFIG_H
#include "nfq-proxy-config.h"
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

struct Object
{
	OBJECT_COMMON
};


/**
* Object Operations
*/
struct Object_ops
{
	/** Unique name of the filter */
	char * obj_name;
	
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

