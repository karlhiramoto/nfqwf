
#ifdef HAVE_CONFIG_H
#include "nfq-web-filter-config.h"
#endif

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>


#include "PrivData.h"
#include "nfq_wf_private.h"

struct priv_data {
	int key;
	void *data;
	void (*free_fn)(void *ptr);
};

struct PrivData
{
	/* array of pointers to private data*/
	struct priv_data **priv_data_vec;
	unsigned int priv_data_count;
};


/** Allocate new private data structure */
struct PrivData *PrivData_new(void) {
	struct PrivData *pd;
	pd = calloc(1, sizeof(struct PrivData));
	pd->priv_data_vec = calloc(1, sizeof(struct priv_data*) * 2);
	return pd;
}

/** Release memory */
void PrivData_del(struct PrivData **pd_in) {
	struct PrivData *pd = *pd_in;
	int i;
	
	// free private data
	for (i = 0 ; i <= pd->priv_data_count; i++) {
		if (pd->priv_data_vec[i]) {
			if (pd->priv_data_vec[i]->data)
				pd->priv_data_vec[i]->free_fn(pd->priv_data_vec[i]->data);
			
			free(pd->priv_data_vec[i]);
		}
	}
	free(pd->priv_data_vec);
	free(pd);
	*pd_in = NULL;
}

/**
*  @brief create new private data item
*  @arg Private data struct
*  @arg key Access control key to private data
*  @arg size of data to allocate
*  @arg free_fn  function to free the data.  may be free() or customized function
*  @returns pointer to newly allocated data 
*/
void *PrivData_newData(struct PrivData* pd, int key, int size, void (*free_fn)(void *))
{
	void *data;
	
	//NOTE we could check if the key already exists, but that would just slow us down,
	// this would become O(N) where N is number of priv data.   Now we are O(1)
	
	pd->priv_data_vec = realloc(pd->priv_data_vec,
		(pd->priv_data_count+2) * sizeof(struct priv_data*));

	pd->priv_data_vec[pd->priv_data_count] = calloc(1, sizeof(struct priv_data));
	data = pd->priv_data_vec[pd->priv_data_count]->data = calloc(1, size);
	pd->priv_data_vec[pd->priv_data_count]->key = key;
	pd->priv_data_vec[pd->priv_data_count]->free_fn = free_fn;
	pd->priv_data_count++;
	pd->priv_data_vec[pd->priv_data_count] = NULL; // NULL term
	return data;
}

/**
*  @brief create new private data item
*  @arg Private data struct
*  @arg key Access control key to private data
*  @returns pointer to data, or NULL if not found
*/
void *PrivData_getData(struct PrivData* pd, int key)
{
	int i;
	
	for (i = 0; i < pd->priv_data_count; i++) {
		if (pd->priv_data_vec[i] && pd->priv_data_vec[i]->key == key) {
			DBG(5, "found data %p with key %d=0x%08x\n",
				pd->priv_data_vec[i]->data, key, key);
			return pd->priv_data_vec[i]->data;
		}
	}
	return NULL;
}


