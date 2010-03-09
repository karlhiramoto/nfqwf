#ifndef OBJECT_H
#define OBJECT_H

#define OBJECT_COMMON \
int id;\
int refcount; \
struct object_ops *obj_ops;

struct object
{
	OBJECT_COMMON
};

struct object_ops
{
	/** Unique name of the filter */
	char * obj_name;
	
	/** Size of object */
	size_t obj_size;
	
	/**
	* Optional callback to init/allocate any private data
	*/
	int (*obj_constructor)(struct object *);
	
	/**
	* Optional callback to free any private data
	*/
	int (*obj_destructor)(struct object *);
	
	/*optional callback to clone private data */
	int (*obj_clone)(struct object *dst, struct object *src);
	
	/*optional callback to compare two objects */
	int (*obj_compare)(struct object *dst, struct object *src);
	
};

struct object *object_alloc(struct object_ops *ops);

void object_free(struct object *obj);

/**
* @name Reference Management
* @{
*/

/**
* Acquire a reference on a object
* @arg obj  	object to acquire reference from
*/
void object_get(struct object *obj);


/**
* Release a reference from an object
* @arg obj		object to release reference from
*/
void object_put(struct object *obj);

/**
* Check whether this object is used by multiple users
* @arg obj		object to check
* @return true or false
*/
int object_shared(struct object *obj);





#endif

