#ifndef NFQ_WF_PRIVATE_H
#define NFQ_WF_PRIVATE_H

#ifdef HAVE_CONFIG_H
#include "nfq-web-filter-config.h"
#endif

#include <stdio.h>
#include <assert.h>
#include <syslog.h>

#define BUG()                \
	do {                 \
		fprintf(stderr, "BUG: %s:%d\n",  \
		__FILE__, __LINE__);         \
		fflush(stderr); \
		fflush(stdout); \
		assert(0);	\
	} while (0)

/* program name is package name from config.h*/
#define PROG_NAME PACKAGE

#define PRINT(FMT,ARG...) printf(PROG_NAME": " FMT, ##ARG); \
	

extern int debug_level;
#ifdef STATIC_DEBUG
#ifndef DEBUG_LEVEL
	#define DEBUG_LEVEL 9
#endif
#define DBG(LVL,FMT,ARG...) \
	if (LVL <= DEBUG_LEVEL) {\
		fprintf(stderr, PROG_NAME"<" #LVL ">:%s:%d: " FMT, __FUNCTION__, __LINE__, ##ARG); \
	}
#else
/*Dynamic debug levels */
#define DEBUG_LEVEL debug_level
#define DBG(LVL,FMT,ARG...) \
	if (LVL <= debug_level) {\
		fprintf(stderr, PROG_NAME"<" #LVL ">:%s:%d: " FMT, __FUNCTION__, __LINE__, ##ARG); \
	}
#endif

#define CRIT(FMT,ARG...) { \
fprintf(stderr, PROG_NAME " Critical:%s:%d: " FMT, __FUNCTION__, __LINE__, ##ARG); \
syslog(LOG_CRIT, PROG_NAME " Critical:%s:%d: " FMT, __FUNCTION__, __LINE__, ##ARG); \
}

#define ERROR(FMT,ARG...) { \
	fprintf(stderr, PROG_NAME " Error:%s:%d: " FMT, __FUNCTION__, __LINE__, ##ARG); \
	syslog(LOG_ERR, PROG_NAME " Error:%s:%d: " FMT, __FUNCTION__, __LINE__, ##ARG); \
	}

#define WARN(FMT,ARG...) { \
	fprintf(stderr, PROG_NAME " Warning:%s:%d: " FMT, __FUNCTION__, __LINE__, ##ARG); \
	syslog(LOG_WARNING, PROG_NAME " Warning:%s:%d: " FMT, __FUNCTION__, __LINE__, ##ARG); \
	}

#define ERROR_FATAL(FMT,ARG...) { CRIT(FMT, ##ARG); BUG(); }


#define __init __attribute__ ((constructor))
#define __exit __attribute__ ((destructor))
#define likely(x)       __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)


#define XML_ROOT_NODE_NAME "WebFilter"
#define FILTER_ID_XML_PROP "Filter_ID"
#define RULE_ID_XML_PROP "Rule_ID"
#define GROUP_XML_PROP "group"

#endif /* NFQ_WF_PRIVATE_H */

