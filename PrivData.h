
#ifdef HAVE_CONFIG_H
#include "nfq-web-filter-config.h"
#endif

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>



/** Allocate new */
struct PrivData *PrivData_new(void);

/** Release memory */
void PrivData_del(struct PrivData **pd_in);


void *PrivData_newData(struct PrivData* pd, int key, int size, void (*free_fn)(void *));

void *PrivData_getData(struct PrivData* pd, int key);
