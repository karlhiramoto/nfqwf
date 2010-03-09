#ifndef FILTER_OBJECT_LIST_H
#define FILTER_OBJECT_LIST_H


struct FilterList;

struct FilterList*  FilterList_new(void);

struct FilterList* FilterList_add_tail(struct FilterList *fl, struct Filter *fo);

#endif