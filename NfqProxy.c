#include <stdlib.h>
#include <pthread.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <netlink/netfilter/nfnl.h>
#include <netlink/netfilter/queue.h>
#include <netlink/netfilter/queue_msg.h>
#include <netlink/msg.h>
#include <netlink/object.h>


#ifdef HAVE_CONFIG_H
#include "nfq-proxy-config.h"
#endif


#include "HttpReq.h"
#include "HttpConn.h"
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


/**
* NfqProxy object.   This will be a thread that operates on one queue
*/
struct NfqProxy
{
	/** base class members */
	OBJECT_COMMON;

	/** NF_QUEUE Id number*/
	int q_id;

	bool keep_running; /*!< should we keep running */
	pthread_t thread_id;  /*!< This threads ID */

	/** configuration, that contains rules, etc */
	struct ProxyConfig *config;

	/** libnl socket that we will receive queue messages on */
	struct nl_sock *nf_sock;

	/** libnl NF_QUEUE configuration. */
	struct nfnl_queue *nl_queue;

	/** Linked list of connections we are tracking */
	HttpConn_list_t *con_list;  
};

/**
* @name Reference Management
* @{
*/

/** Get a reference counter */
void NfqProxy_get(struct NfqProxy *nfq_proxy) {
	Object_get((struct Object*)nfq_proxy);
}

/** Release reference counter */
void NfqProxy_put(struct NfqProxy **nfq_proxy) {
	
	DBG(4, "removing proxy reference to %p refcount = %d\n",
		*nfq_proxy, (*nfq_proxy)->refcount);
		
	Object_put((struct Object**)nfq_proxy);
}

/** @} */

/**
* @name Constructor and Destructor
* @{
*/

/**
*  Objects constructor
*  @arg Object that was just allocated
*/
int NfqProxy_constructor(struct Object *obj)
{
	struct NfqProxy *nfq_proxy = (struct NfqProxy *)obj;
	DBG(5, " constructor %p\n", nfq_proxy);

	nfq_proxy->nf_sock = nfnl_queue_socket_alloc();
	if (nfq_proxy->nf_sock == NULL) {
		ERROR_FATAL("Unable to allocate netlink socket\n");
	}

	nl_socket_disable_seq_check(nfq_proxy->nf_sock);

	return 0;
}

/**
*  Objects destructor
*  @arg Object that is going to be free'd
*/
int NfqProxy_destructor(struct Object *obj)
{
	struct NfqProxy *nfq_proxy = (struct NfqProxy *)obj;
	DBG(5, " destructor %p\n", nfq_proxy);

	if (nfq_proxy->nl_queue)
		nfnl_queue_put(nfq_proxy->nl_queue);

	nl_socket_free(nfq_proxy->nf_sock);
	return 0;
}
/** @} */


/**
* Object operations
*/
static struct Object_ops obj_ops = {
	.obj_name           = "NfqProxy",
	.obj_size           = sizeof(struct NfqProxy),
	.obj_constructor    = NfqProxy_constructor,
	.obj_destructor     = NfqProxy_destructor,
	
};

/**
* Allocate object
*/
static struct NfqProxy* NfqProxy_alloc(struct Object_ops *ops)
{
	struct NfqProxy *nfq_proxy;
	
	nfq_proxy = (struct NfqProxy*) Object_alloc(ops);
	
	return nfq_proxy;
}



static void __obj_input(struct nl_object *obj, void *arg)
{
	struct NfqProxy* nfq_proxy = arg;
	struct nfnl_queue_msg *msg = (struct nfnl_queue_msg *) obj;
	struct nl_dump_params dp = {
		.dp_type = NL_DUMP_STATS,
		.dp_fd = stdout,
		.dp_dump_msgtype = 1,
	};
// 	int ret;
// 	int len;
// 	void *payload = (void *)nfnl_queue_msg_get_payload(msg, &len);

	DBG(1, " starting nfq_proxy=%p\n", nfq_proxy);
	nfnl_queue_msg_set_verdict(msg, NF_ACCEPT);
	nl_object_dump(obj, &dp);
// 	print_packet(msg);
/*	ret = replace_str_in_pkt(msg, "world", "mundo");
	if (ret > 0) {
		DBG(1, " Send modified packet\n");
		nfnl_queue_msg_send_verdict_payload(nf_sock,
											msg, payload, len);
	} else*/
	nfnl_queue_msg_send_verdict(nfq_proxy->nf_sock, msg);
}

static int __event_input(struct nl_msg *msg, void *arg)
{
// 	struct NfqProxy* nfq_proxy = arg;
	DBG(1, " starting arg=%p\n", arg);
	if (nl_msg_parse(msg, &__obj_input, arg) < 0)
		ERROR("<<EVENT>> Unknown message type\n");

	DBG(1, " returning \n");
	/* Exit nl_recvmsgs_def() and return to the main select() */
	return NL_STOP;
}

static void* __NfqProxy_main(void *arg)
{
	struct NfqProxy* nfq_proxy = arg;
	fd_set rfds;
	int fd, retval;
	struct timeval timeout = { .tv_sec = 3, .tv_usec = 0}; // OPTIMIZE remove and use otherway to exit select

	DBG(5, " thread main startup %p q=%d\n", nfq_proxy, nfq_proxy->q_id);
	while (nfq_proxy->keep_running) {
		DBG(5, " running thread main loop %p q=%d\n", nfq_proxy, nfq_proxy->q_id);

		FD_ZERO(&rfds);

		fd = nl_socket_get_fd(nfq_proxy->nf_sock);
		FD_SET(fd, &rfds);

		/* wait for an incoming message on the netlink socket */
		retval = select(fd+1, &rfds, NULL, NULL, &timeout);

		if (retval) {
			if (FD_ISSET(fd, &rfds)) {
				DBG(1," nf_sock fd %d set\n", fd);
				nl_recvmsgs_default(nfq_proxy->nf_sock);
			}
		}
	}

	return NULL;
}

/**
* Create new NfqProxy object
* @arg q_id   queue number that we will operate on
* @arg conf   configuration see @link ProxyConfig
*/
struct NfqProxy* NfqProxy_new(int q_id, struct ProxyConfig *conf)
{
	struct NfqProxy *nfq_proxy = NfqProxy_alloc(&obj_ops);
	int err;

	nfq_proxy->q_id = q_id;
	nfq_proxy->config = conf;
	nl_socket_modify_cb(nfq_proxy->nf_sock, NL_CB_VALID, NL_CB_CUSTOM, __event_input, nfq_proxy);


	if ((err = nl_connect(nfq_proxy->nf_sock, NETLINK_NETFILTER)) < 0) {
		ERROR_FATAL("Unable to connect netlink socket: %d %s", err,
			nl_geterror(err));
	}

	nfnl_queue_pf_unbind(nfq_proxy->nf_sock, AF_INET);
	if ((err = nfnl_queue_pf_bind(nfq_proxy->nf_sock, AF_INET)) < 0) {
	   ERROR_FATAL("Unable to bind logger: %d %s", err,
			nl_geterror(err));
	}
	nfq_proxy->nl_queue = nfnl_queue_alloc();
	nfnl_queue_set_group(nfq_proxy->nl_queue, nfq_proxy->q_id);

	nfnl_queue_set_copy_mode(nfq_proxy->nl_queue, NFNL_QUEUE_COPY_PACKET);

	nfnl_queue_set_copy_range(nfq_proxy->nl_queue, 0xFFFF);

	if ((err = nfnl_queue_create(nfq_proxy->nf_sock,nfq_proxy->nl_queue)) < 0) {
		ERROR_FATAL("Unable to bind queue: %d %s", err, nl_geterror(err));
	}

	return nfq_proxy;
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

/**
* Tell the thread it should stop running
* @arg  Proxy object
* @return 0 if OK
*/
int NfqProxy_stop(struct NfqProxy* nfq_proxy)
{
	nfq_proxy->keep_running = false;
	return 0;
}

/**
* block on pthread_join()
* @arg  Proxy object
* @return 0 if OK
*/
int NfqProxy_join(struct NfqProxy* nfq_proxy)
{
	DBG(5, "Join proxy thread %p\n", nfq_proxy);
	return pthread_join(nfq_proxy->thread_id, NULL);
}


/** @} */

