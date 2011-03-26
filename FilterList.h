/*
Copyright (C) <2010-2011> Karl Hiramoto <karl@hiramoto.org>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

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
