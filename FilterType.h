#ifndef FILTERS_H
#define FILTERS_H

struct Filter_ops;
struct Filter;

int FilterType_register(struct Filter_ops *ops);

struct Filter *FilterType_get_new(const char *name);

#endif /* FILTERS_H */

