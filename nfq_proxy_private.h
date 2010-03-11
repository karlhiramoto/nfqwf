#ifndef NFQ_PROXY_PRIVATE_H
#define NFQ_PROXY_PRIVATE_H

#ifdef HAVE_CONFIG_H
#include "nfq-proxy-config.h"
#endif

#include <stdio.h>
#include <assert.h>

#define BUG()                \
	do {                 \
		fprintf(stderr, "BUG: %s:%d\n",  \
		__FILE__, __LINE__);         \
		fflush(stderr); \
		assert(0);	\
	} while (0)

#define DEBUG_LEVEL 9

#define DBG(LVL,FMT,ARG...) \
	if (LVL <= DEBUG_LEVEL) {\
		fprintf(stderr, "WebProxy<" #LVL ">:%s:%d: " FMT, __FUNCTION__, __LINE__, ##ARG); \
	}

#define ERROR(FMT,ARG...) { fprintf(stderr, "Error:%s:%d: " FMT, __FUNCTION__, __LINE__, ##ARG); }

#define ERROR_FATAL(FMT,ARG...) { ERROR(FMT, ##ARG); BUG(); }


#define __init __attribute__ ((constructor))
#define __exit __attribute__ ((destructor))



#endif /* NFQ_PROXY_PRIVATE_H */

