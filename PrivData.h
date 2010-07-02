
#ifdef HAVE_CONFIG_H
#include "nfq-web-filter-config.h"
#endif

struct PrivData *PrivData_new(void);

void PrivData_del(struct PrivData **pd_in);


void *PrivData_newData(struct PrivData* pd, int key, int size, void (*free_fn)(void *));

void *PrivData_getData(struct PrivData* pd, int key);
