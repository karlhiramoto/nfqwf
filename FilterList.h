#ifndef FILTER_OBJECT_LIST_H
#define FILTER_OBJECT_LIST_H


struct FilterList;

struct FilterList*  FilterList_new(void);

void FilterList_free(struct FilterList **fl);

struct FilterList* FilterList_addTail(struct FilterList *fl, struct Filter *fo);

struct Filter* FilterList_searchObjId(struct FilterList *fl, int id);


#endif