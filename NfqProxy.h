#ifndef NFQ_PROXY
#define NFQ_PROXY 1

// #include <pthread.h>



#include "HttpReq.h"
#include "HttpConn.h"

// struct NfqProxy {
// 	int q_id; /* NF_QUEUE ID*/
// 	struct ProxyConfig *config;
// 	HttpConn_list_t *con_list;
// };
struct ProxyConfig;
struct NfqProxy;

void NfqProxy_put(struct NfqProxy **nfq_proxy);

struct NfqProxy* NfqProxy_new(int q_id, struct ProxyConfig *config);

int NfqProxy_updateConfig(struct NfqProxy *nfqp, struct ProxyConfig *config);

int NfqProxy_start(struct NfqProxy* nfq_proxy);

int NfqProxy_stop(struct NfqProxy* nfq_proxy);

int NfqProxy_join(struct NfqProxy* nfq_proxy);

#endif
