#include <stdlib.h>

#include "Filter.h"

// #include "Filter_list.h"
#include "nfq_proxy_private.h"



struct FilterList {
	unsigned int count;
	struct Filter **list;
};


struct FilterList* FilterList_new(void)
{
	return calloc(1, sizeof(struct FilterList));
}

void FilterList_free(struct FilterList **fl_in)
{
	struct FilterList *fl = *fl_in;
	unsigned i;
	struct Filter *fo;

	if (!fl || !fl_in)
		BUG();
	
	for (i = 0; fl->list && fl->list[i]; i++) {
		fo = fl->list[i];
		Filter_put(&fo);
	}
	
	free(fl->list);
	free(*fl_in);
	*fl_in = NULL;
}

struct FilterList* FilterList_addTail(struct FilterList *fl, struct Filter *fo)
{
	fl->list = realloc(fl->list, (sizeof(struct Filter *) * (fl->count+2)));
	
	if (!fl)
		return NULL;

	DBG(5, "Add new object %p to list %p count =%d \n", fo, fl, fl->count);

	fl->list[fl->count] = fo;
	fl->count++;
	fl->list[fl->count] = NULL;

	return fl;
}

struct Filter* FilterList_searchObjId(struct FilterList *fl, int id)
{
	//TODO
	return NULL;
}