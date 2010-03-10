#ifndef FILTER_OBJECT_LIST_H
#define FILTER_OBJECT_LIST_H

/**
* @ingroup  Object
* @defgroup FilterList FilterList. A list/vector of filters
* @brief This is a way to create a list or group of @link FilterObject
* @{
*/
struct FilterList;

struct FilterList*  FilterList_new(void);

void FilterList_free(struct FilterList **fl);

struct FilterList* FilterList_addTail(struct FilterList *fl, struct Filter *fo);

struct Filter* FilterList_searchObjId(struct FilterList *fl, int id);
/** @} */

#endif