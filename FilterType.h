#ifndef FILTERS_H
#define FILTERS_H

#ifdef HAVE_CONFIG_H
#include "nfq-proxy-config.h"
#endif

struct Filter_ops;
struct Filter;

int FilterType_register(struct Filter_ops *ops);

struct Filter *FilterType_get_new(const char *name);

#endif /* FILTERS_H */

