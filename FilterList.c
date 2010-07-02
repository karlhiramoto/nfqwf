#include <stdlib.h>

#include "Filter.h"
#include "FilterList.h"

// #include "Filter_list.h"
#include "nfq_wf_private.h"



struct FilterList {
	unsigned int count;
	struct Filter **list;
};


struct FilterList* FilterList_new(void)
{
	return calloc(1, sizeof(struct FilterList));
}

void FilterList_del(struct FilterList **fl_in)
{
	struct FilterList *fl = *fl_in;
	unsigned i;
	struct Filter *fo;

	if (!fl || !fl_in)
		BUG();
	
	for (i = 0; fl->list && fl->list[i]; i++) {
		fo = fl->list[i];
		DBG(5, " free filter %d = %p\n", i, fo);
		Filter_put(&fo);
	}
	
	free(fl->list);
	free(*fl_in);
	*fl_in = NULL;
}

struct FilterList* FilterList_addTail(struct FilterList *fl, struct Filter *fo)
{
	DBG(5, "Adding new object %p to list %p\n", fo, fl);

	fl->list = realloc(fl->list, (sizeof(struct Filter *) * (fl->count+2)));

	if (!fl)
		return NULL;


	Filter_get(fo);
	fl->list[fl->count] = fo;
	fl->count++;
	fl->list[fl->count] = NULL;

	return fl;
}

/**return true if the FilterList contains Filter, else return false */
bool FilterList_contains(struct FilterList *fl, struct Filter *fo)
{
	unsigned int i;
	for (i= 0; i < fl->count ; i++) {
		if (fl->list[i] == fo)
			return true;
	}
	return false;
}

struct Filter* FilterList_searchFilterId(struct FilterList *fl, unsigned int id)
{
	int i;

	for (i = 0 ; i < fl->count; i++) {
		if (fl->list[i] && Filter_getFilterId(fl->list[i]) == id )
			return fl->list[i];
	}
	return NULL;
}


unsigned int FilterList_count(struct FilterList *fl)
{
	return fl->count;
}

int FilterList_foreach(struct FilterList *fl, void *data, int (*cb_func)(struct Filter *, void *))
{
	int i;
	int rc = 0;
	for (i = 0 ; i < fl->count; i++) {
		if (fl->list[i])
			rc |= cb_func(fl->list[i], data);
	}
	return rc;
}

