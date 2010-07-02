#ifndef FILTER_OBJECT_LIST_H
#define FILTER_OBJECT_LIST_H

#include <stdbool.h>
/**
* @ingroup  Object
* @defgroup FilterList FilterList. A list/vector of filters
* @brief This is a way to create a list or group of @link FilterObject
* @{
*/
struct FilterList;
struct Filter;

struct FilterList*  FilterList_new(void);

void FilterList_del(struct FilterList **fl);

struct FilterList* FilterList_addTail(struct FilterList *fl, struct Filter *fo);

bool FilterList_contains(struct FilterList *fl, struct Filter *fo);


struct Filter* FilterList_searchFilterId(struct FilterList *fl, unsigned int id);

unsigned int FilterList_count(struct FilterList *fl);

int FilterList_foreach(struct FilterList *fl, void *data, int (*cb_func)(struct Filter *, void *));

/** @} */

#endif
