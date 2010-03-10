#ifndef NFQ_PROXY
#define NFQ_PROXY 1

// #include <pthread.h>


/**
* @defgroup Proxy NFQ Proxy.  Thread that operates on a single NF_QUEUE
* @brief We will handle all of the packets at arrive on this queue.
* @{
*/

 
#include "HttpReq.h"

struct NfqProxy {
	int q_id; /* NF_QUEUE ID*/
	struct ProxyConfig *config;
	HttpConn_list_t *con_list;
};

struct NfqProxy *NfqProxy_new(int q_id, struct ProxyConfig *config);

int NfqProxy_updateConfig(struct NfqProxy *nfqp, struct ProxyConfig *config);

/** Thread main loop */
void *NfqProxy_run(void *NfqProxy);

#endif