#include <stdlib.h>
#include <pthread.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#ifdef HAVE_CONFIG_H
#include "nfq-proxy-config.h"
#endif

#include "NfqProxy.h"
#include "FilterType.h"
#include "FilterList.h"
#include "Rules.h"
#include "nfq_proxy_private.h"

/**
* @ingroup Object
* @defgroup Proxy NFQ Proxy.  Thread that operates on a single NF_QUEUE
* @brief We will handle all of the packets at arrive on this queue.
* @{
*/


struct NfqProxy
{
	OBJECT_COMMON
	int q_id; /* NF_QUEUE ID*/
	bool keep_running;
	pthread_t thread_id;
	struct ProxyConfig *config;
	HttpConn_list_t *con_list;
};


void NfqProxy_get(struct NfqProxy *nfq_proxy) {
	Object_get((struct Object*)nfq_proxy);
}

void NfqProxy_put(struct NfqProxy **nfq_proxy) {
	
	DBG(4, "removing proxy reference to %p refcount = %d\n",
		*nfq_proxy, (*nfq_proxy)->refcount);
		
	Object_put((struct Object**)nfq_proxy);
}

int NfqProxy_constructor(struct Object *obj)
{
	struct NfqProxy *nfq_proxy = (struct NfqProxy *)obj;
	DBG(5, " constructor %p\n", nfq_proxy);
	return 0;
}

int NfqProxy_destructor(struct Object *obj)
{
	struct NfqProxy *nfq_proxy = (struct NfqProxy *)obj;
	DBG(5, " destructor %p\n", nfq_proxy);
	
	return 0;
}


static struct Object_ops obj_ops = {
	.obj_name           = "NfqProxy",
	.obj_size           = sizeof(struct NfqProxy),
	.obj_constructor    = NfqProxy_constructor,
	.obj_destructor     = NfqProxy_destructor,
	
};

static struct NfqProxy* NfqProxy_alloc(struct Object_ops *ops)
{
	struct NfqProxy *nfq_proxy;
	
	nfq_proxy = (struct NfqProxy*) Object_alloc(ops);
	
	return nfq_proxy;
}

struct NfqProxy* NfqProxy_new(int q_id, struct ProxyConfig *conf)
{
	return NfqProxy_alloc(&obj_ops);
}

static void* __NfqProxy_main(void *arg)
{
	struct NfqProxy* nfq_proxy = arg;

	DBG(5, " thread main startup %p\n", nfq_proxy);
	while (nfq_proxy->keep_running) {
		sleep(1);  // FIXME remove when recieving packets.
		DBG(5, " running thread main loop %p\n", nfq_proxy);
	}

	return NULL;
}



/** Start thread main loop
* @arg  Proxy object
* @return thread ID, or -errno
*/
int NfqProxy_start(struct NfqProxy* nfq_proxy)
{
	int ret;
	nfq_proxy->keep_running = true;

	ret = pthread_create(&nfq_proxy->thread_id, NULL, __NfqProxy_main, nfq_proxy);

	return ret;
}

int NfqProxy_stop(struct NfqProxy* nfq_proxy)
{
	nfq_proxy->keep_running = false;
	return 0;
}

int NfqProxy_join(struct NfqProxy* nfq_proxy)
{
	DBG(5, "Join proxy thread %p\n", nfq_proxy);
	return pthread_join(nfq_proxy->thread_id, NULL);
}


/** @} */