#include <stdlib.h>

// #include "Filter_list.h"
#include "nfq_proxy_private.h"



struct FilterList {
	unsigned int FilterList_count;
	struct Filter **FilterList;
};


struct FilterList* FilterList_new(void)
{
	return calloc(1, sizeof(struct FilterList));
}

struct FilterList* FilterList_add_tail(struct FilterList *fl, struct Filter *fo)
{
	fl = realloc(fl, (sizeof(struct Filter *) + fl->FilterList_count+2));
	
	if (!fl)
		return NULL;
	
	fl->FilterList[fl->FilterList_count] = fo;
	fl->FilterList_count++;
	fl->FilterList[fl->FilterList_count] = NULL;

	return fl;
}

struct Filter* FilterList_search_obj_id(struct FilterList *fl, int id)
{
	//TODO
	return NULL;
}