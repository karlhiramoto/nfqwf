#include <pthread.h>
#include <stdlib.h>
#include <pthread.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netinet/in.h>
#include <linux/netfilter.h>

#include <netlink/netfilter/nfnl.h>
#include <netlink/netfilter/queue.h>
#include <netlink/netfilter/queue_msg.h>
#include <netlink/msg.h>
#include <netlink/object.h>
#include <arpa/inet.h>

#ifdef HAVE_CONFIG_H
#include "nfq-web-filter-config.h"
#endif


#include "HttpReq.h"
#include "HttpConn.h"
#include "NfQueue.h"
#include "FilterType.h"
#include "FilterList.h"
#include "Rules.h"
#include "WfConfig.h"
#include "nfq_wf_private.h"

#define CONNECTION_TIMEOUT 600

// Timeout if one side has closed
#define CON_FIN_TIMEOUT 60
#define MAX(a, b) (a > b ? a : b)
#define MIN(a, b) (a < b ? a : b)

/**
* @ingroup Object
* @defgroup NFQueue NFQueue thread that operates on a single NF_QUEUE
* @brief We will handle all of the packets at arrive on this queue.
* @{
*/


/**
* NfQueue object.   This will be a thread that operates on one netfilter queue
*/
struct NfQueue
{
	/** base class members */
	OBJECT_COMMON;

	/** NF_QUEUE Id number*/
	int q_id;
	uint32_t last_packet_id;

	bool keep_running; /*!< should we keep running */
	int exit_pipe[2]; /*!< Write to this pipe to break out of select() */
	pthread_t thread_id;  /*!< This threads ID */

	/** configuration, that contains rules, etc */
	struct WfConfig *config;
	pthread_mutex_t config_mutex;

	/** libnl socket that we will receive queue messages on */
	struct nl_sock *nf_sock;

	/** libnl NF_QUEUE configuration. */
	struct nfnl_queue *nl_queue;

	/** Linked list of connections we are tracking */
	HttpConn_list_t *con_list;
};



static void __httpConnList_rmCon(struct NfQueue* nfq_wf, struct HttpConn* con)
{
	ubi_dlRemThis(nfq_wf->con_list, con);
	HttpConn_del(&con);
}

/**
* @name Reference Management
* @{
*/

/** Get a reference counter */
void NfQueue_get(struct NfQueue *nfq_wf) {
	Object_get((struct Object*)nfq_wf);
}

/** Release reference counter */
void NfQueue_put(struct NfQueue **nfq_wf) {

	DBG(4, "removing proxy reference to %p refcount = %d\n",
		*nfq_wf, (*nfq_wf)->refcount);

	Object_put((struct Object**)nfq_wf);
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
int NfQueue_constructor(struct Object *obj)
{
	struct NfQueue *nfq_wf = (struct NfQueue *)obj;
	DBG(5, " constructor %p\n", nfq_wf);

	pthread_mutex_init(&nfq_wf->config_mutex, NULL);

	nfq_wf->nf_sock = nfnl_queue_socket_alloc();
	if (nfq_wf->nf_sock == NULL) {
		ERROR_FATAL("Unable to allocate netlink socket\n");
	}

	nl_socket_disable_seq_check(nfq_wf->nf_sock);

	nfq_wf->con_list = malloc(sizeof(HttpConn_list_t));
	nfq_wf->con_list = ubi_dlInitList(nfq_wf->con_list);

	return 0;
}

/**
*  Objects destructor
*  @arg Object that is going to be free'd
*/
int NfQueue_destructor(struct Object *obj)
{
	struct NfQueue *nfq_wf = (struct NfQueue *)obj;
	struct HttpConn* con = NULL;
	struct HttpConn* next_con = NULL;

	DBG(5, " destructor %p\n", nfq_wf);

	if (nfq_wf->nl_queue)
		nfnl_queue_put(nfq_wf->nl_queue);

	nl_socket_free(nfq_wf->nf_sock);

	if (nfq_wf->exit_pipe[0])
		close(nfq_wf->exit_pipe[0]);

	if (nfq_wf->exit_pipe[1])
		close(nfq_wf->exit_pipe[1]);

	if (ubi_dlCount(nfq_wf->con_list)) {
		DBG(1, "Warning %lu HTTP connections in list before free\n",
			ubi_dlCount(nfq_wf->con_list));

			next_con = (struct HttpConn *)ubi_dlFirst(nfq_wf->con_list);
			/*while list not empty */
			while(next_con) {
				con = next_con;
				next_con = (struct HttpConn *)ubi_dlNext(next_con);
				__httpConnList_rmCon(nfq_wf, con);
			}
	}
	WfConfig_put(&nfq_wf->config);
	free(nfq_wf->con_list);
	return 0;
}
/** @} */


/**
* Object operations
*/
static struct Object_ops obj_ops = {
	.obj_type           = "NfQueue",
	.obj_size           = sizeof(struct NfQueue),
	.obj_constructor    = NfQueue_constructor,
	.obj_destructor     = NfQueue_destructor,

};

/**
* Allocate object
*/
static struct NfQueue* NfQueue_alloc(struct Object_ops *ops)
{
	struct NfQueue *nfq_wf;

	nfq_wf = (struct NfQueue*) Object_alloc(ops);

	return nfq_wf;
}


#if 0
static void __obj_input(struct nl_object *obj, void *arg)
{
	struct NfQueue* nfq_wf = arg;
	struct nfnl_queue_msg *msg = (struct nfnl_queue_msg *) obj;
// 	struct nl_dump_params dp = {
// 		.dp_type = NL_DUMP_STATS,
// 		.dp_fd = stdout,
// 		.dp_dump_msgtype = 1,
// 	};
	uint32_t packet_id = nfnl_queue_msg_get_packetid(msg);
	static uint32_t next_packet_id = 0;
	struct nfnl_queue_msg *lost_msg = NULL;
	uint8_t family;
	uint16_t group;

	if (packet_id > next_packet_id) {
		printf("Warning: %d Out of order packets.  Queue or socket overload \n", packet_id - next_packet_id);
		group = nfnl_queue_msg_get_group(msg);
		family = nfnl_queue_msg_get_family(msg);
		lost_msg = nfnl_queue_msg_alloc();

		do {
			nfnl_queue_msg_set_group(lost_msg, group);
			nfnl_queue_msg_set_family(lost_msg, family);
			nfnl_queue_msg_set_packetid(lost_msg, next_packet_id);
			nfnl_queue_msg_set_verdict(lost_msg, NF_ACCEPT);
			nfnl_queue_msg_send_verdict(nfq_wf->nf_sock, lost_msg);
			next_packet_id++;
		} while (packet_id > next_packet_id);
		nfnl_queue_msg_put(lost_msg);
	}

	next_packet_id = packet_id + 1;

// 	DBG(1, " starting nfq_wf=%p\n", nfq_wf);
	nfnl_queue_msg_set_verdict(msg, NF_ACCEPT);
//  	nl_object_dump(obj, &dp);
// 	print_packet(msg);
/*	ret = replace_str_in_pkt(msg, "world", "mundo");
	if (ret > 0) {
		DBG(1, " Send modified packet\n");
		nfnl_queue_msg_send_verdict_payload(nf_sock,
											msg, payload, len);
	} else*/
	nfnl_queue_msg_send_verdict(nfq_wf->nf_sock, msg);
}

static int __event_input(struct nl_msg *msg, void *arg)
{
// 	struct NfQueue* nfq_wf = arg;
	DBG(1, " starting arg=%p\n", arg);
	if (nl_msg_parse(msg, &__obj_input, arg) < 0)
		ERROR("<<EVENT>> Unknown message type\n");

	DBG(1, " returning \n");
	/* Exit nl_recvmsgs_def() and return to the main select() */
	return NL_STOP;
}
#endif

static struct HttpConn* __httpConnList_expire(struct NfQueue* nfq_wf)
{
	struct HttpConn* con = NULL;
	struct HttpConn* next_con = NULL;
	time_t now = time(NULL);
	time_t delta; // time difference between now and last packet

	next_con = (struct HttpConn *)ubi_dlFirst(nfq_wf->con_list);

	/*for each object in list */
	while (next_con) {
		con = next_con;
		next_con = (struct HttpConn *)ubi_dlNext(con);
		delta = now - con->last_pkt;

		if (delta > CONNECTION_TIMEOUT) {
			DBG(3, "Timeout Con ID=%d No packet in %d seconds.\n",
				con->id, (int) delta);
			__httpConnList_rmCon(nfq_wf, con);
		} else if ( delta > CON_FIN_TIMEOUT
			&& (MAX(con->server_state, con->client_state) > TCP_CONNTRACK_CLOSE_WAIT)) {
			// Timeout connections that one side has closed faster.
			DBG(3, "Close Timeout Con ID=%d No packet in %d seconds.\n",
				con->id, (int) delta);
			__httpConnList_rmCon(nfq_wf, con);
		}
	}

	return NULL;
}
static struct HttpConn* __find_tcp_conn(struct NfQueue* nfq_wf, struct Ipv4TcpPkt *pkt)
{
	struct HttpConn* con = NULL;

#if 0
char src_buf[INET_ADDRSTRLEN+2];
char dst_buf[INET_ADDRSTRLEN+2];

	inet_ntop(AF_INET, &pkt->ip_data[12], src_buf, sizeof(src_buf));
	inet_ntop(AF_INET, &pkt->ip_data[16], dst_buf, sizeof(dst_buf));
	DBG(5, "Searching for SRC_IP=%s DST_IP=%s sport=%u dport=%u\n",
		src_buf, dst_buf, pkt->tuple.src_port, con->tuple.dst_port);
#endif
	/*for each object in list */
	for (con = (struct HttpConn *)ubi_dlFirst(nfq_wf->con_list);
		con; con = (struct HttpConn *)ubi_dlNext(con)) {

		if (!memcmp(&con->tuple, &pkt->tuple, sizeof(struct Ipv4TcpTuple))) {
			return con;
		} else if (con->tuple.dst_ip == pkt->tuple.src_ip &&
				con->tuple.src_ip == pkt->tuple.dst_ip &&
				con->tuple.dst_port == pkt->tuple.src_port &&
				con->tuple.src_port == pkt->tuple.dst_port) {
			return con;
		}

#if DEBUG_LEVEL > 1
// 		inet_ntop(AF_INET, &con->tuple.src_ip, src_buf, sizeof(src_buf));
// 		inet_ntop(AF_INET, &con->tuple.dst_ip, dst_buf, sizeof(dst_buf));

		DBG(5, "No match Con_ID=%u src_ip=0x%08X dst_ip=0x%08X sport=%u dport =%u \n"
			" pkt_dst=0x%08X con_dst=0x%08X p_sport=%d c_sport=%d sstate=%d cstate=%d\n",
			con->id,
			con->tuple.src_ip, con->tuple.dst_ip,
			con->tuple.src_port, con->tuple.dst_port,
			pkt->tuple.src_ip, pkt->tuple.dst_ip,
			pkt->tuple.src_port, con->tuple.src_port,
			con->server_state, con->client_state);
#endif
	}

	return NULL;
}

static void __add_tcp_conn(struct NfQueue* nfq_wf, struct HttpConn* con)
{
	ubi_dlAddHead(nfq_wf->con_list, con);
}

static int __NfQueue_process_pkt(struct NfQueue* nfq_wf, struct Ipv4TcpPkt *pkt)
{
	struct HttpConn* con;
	int ret;

	// by default, may be changed later
	nfnl_queue_msg_set_verdict(pkt->nl_qmsg, NF_ACCEPT);

	con = __find_tcp_conn(nfq_wf, pkt);
	if (!con) {

		if (pkt->tcp_flags &
			(TCP_FLAG_PSH | TCP_FLAG_RST |TCP_FLAG_FIN | TCP_FLAG_ACK )) {

			DBG(1, "Ignore packet no connection found q_id=%d\n", nfq_wf->q_id);

			if (pkt->tcp_payload_length) {
				nfnl_queue_msg_set_verdict(pkt->nl_qmsg, NF_DROP);
			}
			nfnl_queue_msg_send_verdict(nfq_wf->nf_sock, pkt->nl_qmsg);
			return 0;
		}

		pthread_mutex_lock(&nfq_wf->config_mutex);
		con = HttpConn_new(nfq_wf->config);
		pthread_mutex_unlock(&nfq_wf->config_mutex);

		DBG(1, "No TCP connection for this packet. Create New id = %u q_id=%d\n",
			con->id, nfq_wf->q_id)
		if (!con) {
			ERROR_FATAL("No memory\n");
		}
		__add_tcp_conn(nfq_wf, con);
	} else {
		DBG(1, "Packet for TCP connection id = %u q_id=%d\n",
			con->id, nfq_wf->q_id);
	}

	ret = HttpConn_processsPkt(con, pkt);
	DBG(3, "HttpConn_processsPkt returned %d \n", ret)

	if (ret == TCP_CONNTRACK_CLOSE) {
		__httpConnList_rmCon(nfq_wf, con);
	}

	if(pkt->modified_ip_data) {
		DBG(1, "Sending modified IP packet %p of len %d orig packet ptr =%p\n",
			pkt->modified_ip_data, pkt->modified_ip_data_len, pkt->ip_data);
		nfnl_queue_msg_send_verdict_payload(nfq_wf->nf_sock, pkt->nl_qmsg,
			pkt->modified_ip_data, pkt->modified_ip_data_len);

		// if we allocated a new buffer
		if (pkt->modified_ip_data != pkt->ip_data) {
			free(pkt->modified_ip_data);
			pkt->modified_ip_data = NULL;
			pkt->modified_ip_data_len = 0;
		}
	} else {
		if (pkt->nl_qmsg)
			nfnl_queue_msg_send_verdict(nfq_wf->nf_sock, pkt->nl_qmsg);
		else {
			ERROR_FATAL("Skip sending queue verdict \n");
		}
	}


	return 0;
}

static void __NfQueue_check_packet_id(struct NfQueue* nfq_wf, struct Ipv4TcpPkt *pkt)
{
	struct nfnl_queue_msg *lost_msg;
	uint32_t next_packet_id = nfq_wf->last_packet_id + 1;

	if (pkt->packet_id > next_packet_id) {
		WARN("Queue %d overload packet_id=%d next_packet_id=%d delta=%d\n",
			 nfq_wf->q_id, pkt->packet_id, next_packet_id, pkt->packet_id - next_packet_id);
#if 1
		lost_msg = nfnl_queue_msg_alloc();

		do {
			nfnl_queue_msg_set_group(lost_msg, nfq_wf->q_id);
			nfnl_queue_msg_set_family(lost_msg, AF_INET);
			nfnl_queue_msg_set_packetid(lost_msg, next_packet_id);
			/* drop this packet so it clears the netlink buffer */
			nfnl_queue_msg_set_verdict(lost_msg, NF_DROP);
			nfnl_queue_msg_send_verdict(nfq_wf->nf_sock, lost_msg);
			next_packet_id++;
		} while (pkt->packet_id > next_packet_id);
		nfnl_queue_msg_put(lost_msg);
#endif
	}

	nfq_wf->last_packet_id = pkt->packet_id;
}

static int __NfQueue_recv_pkt(struct NfQueue* nfq_wf)
{
	int n, err = 0, multipart = 0;
	unsigned char *buf = NULL;
	struct nlmsghdr *hdr;
	struct sockaddr_nl nla = {0};
	int pkt_counter;
	struct iovec iov;
	struct Ipv4TcpPkt *pkt;
	struct msghdr msg = {
		.msg_name = (void *) &nla,
		.msg_namelen = sizeof(struct sockaddr_nl),
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = NULL,
		.msg_controllen = 0,
		.msg_flags = 0,
	};

	continue_reading:

	iov.iov_len = 2000;
	pkt = Ipv4TcpPkt_new(iov.iov_len);

	// 	iov.iov_len = getpagesize();
	iov.iov_base = buf = pkt->nl_buffer;

	//TODO OPTIMIZE look into new kernel recvmmsg() to reduce system calls
	n = recvmsg(nl_socket_get_fd(nfq_wf->nf_sock), &msg, 0);

	if (n <= 0) {
		Ipv4TcpPkt_del(&pkt);
		return n;
	}

	DBG(3, "Read %d bytes\n", n);

	hdr = (struct nlmsghdr *) buf;
	for(pkt_counter = 0; nlmsg_ok(hdr, n); pkt_counter++) {
		DBG(3, "Processing valid message... hdr=%p buf=%p n=%d\n", hdr, buf, n);

		DBG(3, "nlmsg_len=%d nlmsg_type=%d nlmsg_flags=%d nlmsg_seq=%d nlmsg_pid=%d\n",
			   hdr->nlmsg_len, hdr->nlmsg_type, hdr->nlmsg_flags, hdr->nlmsg_seq, hdr->nlmsg_pid);

		if (hdr->nlmsg_type == NLMSG_DONE ||
			   hdr->nlmsg_type == NLMSG_ERROR ||
			   hdr->nlmsg_type == NLMSG_NOOP ||
			   hdr->nlmsg_type == NLMSG_OVERRUN) {
				/* We can't check for !NLM_F_MULTI since some netlink
			   * users in the kernel are broken. */
			DBG(3, "recvmsgs DONE|ERROR|NOPP|Overrun\n");
		}

		if (hdr->nlmsg_flags & NLM_F_MULTI) {
				DBG(3, "recvmsgs Multipart received\n");
				multipart = 1;
			}

			/* Other side wishes to see an ack for this message */
			if (hdr->nlmsg_flags & NLM_F_ACK) {
				DBG(3, "recvmsgs ACK requested\n");
			}

			/* messages terminates a multpart message, this is
			* usually the end of a message and therefore we slip
			* out of the loop by default. the user may overrule
			* this action by skipping this packet. */
			if (hdr->nlmsg_type == NLMSG_DONE) {
				multipart = 0;
				DBG(3, "recvmsgs DONE\n");
			}

			/* Message to be ignored, the default action is to
			* skip this message if no callback is specified. The
			* user may overrule this action by returning
			* NL_PROCEED. */
			else if (hdr->nlmsg_type == NLMSG_NOOP) {
				DBG(3, "recvmsgs NOOP\n");
			}

			/* Data got lost, report back to user. The default action is to
			* quit parsing. The user may overrule this action by retuning
			* NL_SKIP or NL_PROCEED (dangerous) */
			else if (hdr->nlmsg_type == NLMSG_OVERRUN) {
				DBG(3, "recvmsgs OVERRUN\n");
			}

			/* Message carries a nlmsgerr */
			else if (hdr->nlmsg_type == NLMSG_ERROR) {
				struct nlmsgerr *e = nlmsg_data(hdr);
				DBG(3, "recvmsgs error\n");

				if (hdr->nlmsg_len < (NLMSG_HDRLEN +sizeof(*e))) {
					/* Truncated error message, the default action
					* is to stop parsing. The user may overrule
					* this action by returning NL_SKIP or
					* NL_PROCEED (dangerous) */
					DBG(1, "recvmsgs INVALID/Truncated\n");
				} else if (e->error) {
					/* Error message reported back from kernel. */
					ERROR("recvmsgs Error from kernel ERROR=%d\n", e->error);
				}

			} else {
				/* Valid message (not checking for MULTIPART bit to
				* get along with broken kernels. NL_SKIP has no
				* effect on this.  */
				DBG(3, "recvmsgs VALID\n");

				if (NFNL_SUBSYS_ID(hdr->nlmsg_type) != NFNL_SUBSYS_QUEUE) {
					DBG(1, "WARNING NOT QUEUE MESSAGE\n");
				}

				DBG(3, "q_id=%d family=%d\n",nfnlmsg_res_id(hdr), nfnlmsg_family(hdr));
				err = Ipv4TcpPkt_parseNlHdrMsg(pkt, hdr);
				if (err) {
					ERROR("packet parse error = %d\n", err);
				} else {
					__NfQueue_check_packet_id(nfq_wf, pkt);
					err = __NfQueue_process_pkt(nfq_wf, pkt);
					DBG(3, "__NfQueue_process_pkt= %d\n", err);
				}


			}

		err = 0;
		hdr = nlmsg_next(hdr, &n);
	}

	Ipv4TcpPkt_del(&pkt);
	if (pkt_counter > 1) {
		//NOTE if this occurs Now this is note handled properly
		printf("Multiple messages processed %d\n", pkt_counter);
		abort();
	}

// 	if (buf)
// 		free(buf);
// 	buf = NULL;

	if (multipart) {
		/* Multipart message not yet complete, continue reading */
		goto continue_reading;
	}
	// 	stop:
	err = 0;
	// 	out:
// 	free(buf);

	return err;


}

static void* __NfQueue_main(void *arg)
{
	struct NfQueue* nfq_wf = arg;
	fd_set rfds;
	int fd, retval;
	int err;
	int max_fd;
	struct timeval timeout  = { .tv_sec = 120, .tv_usec = 0 };
	int timeout_pkt_count = 0;

	DBG(5, " thread main startup %p q=%d\n", nfq_wf, nfq_wf->q_id);
// 	nl_socket_modify_cb(nfq_wf->nf_sock, NL_CB_VALID, NL_CB_CUSTOM, __event_input, nfq_wf);


	if ((err = nl_connect(nfq_wf->nf_sock, NETLINK_NETFILTER)) < 0) {
		ERROR_FATAL("Unable to connect netlink socket: %d %s", err,
					nl_geterror(err));
	}

	nfnl_queue_pf_unbind(nfq_wf->nf_sock, AF_INET);
	if ((err = nfnl_queue_pf_bind(nfq_wf->nf_sock, AF_INET)) < 0) {
		ERROR_FATAL("Unable to bind logger: %d %s", err,
					nl_geterror(err));
	}
	nfq_wf->nl_queue = nfnl_queue_alloc();
	nfnl_queue_set_group(nfq_wf->nl_queue, nfq_wf->q_id);
	nfnl_queue_set_maxlen(nfq_wf->nl_queue, 5000);
	nfnl_queue_set_copy_mode(nfq_wf->nl_queue, NFNL_QUEUE_COPY_PACKET);

	nfnl_queue_set_copy_range(nfq_wf->nl_queue, 0xFFFF);

	if ((err = nfnl_queue_create(nfq_wf->nf_sock, nfq_wf->nl_queue)) < 0) {
		ERROR_FATAL("Unable to bind queue: %d %s", err, nl_geterror(err));
	}

	max_fd = fd = nl_socket_get_fd(nfq_wf->nf_sock);
	nl_socket_set_buffer_size(nfq_wf->nf_sock, 1024*127, 1024*127);

	if (nfq_wf->exit_pipe[0] > fd)
		max_fd = nfq_wf->exit_pipe[0];

	while (nfq_wf->keep_running) {
		DBG(5, " running thread main loop %p q=%d\n", nfq_wf, nfq_wf->q_id);

		FD_ZERO(&rfds);

		FD_SET(fd, &rfds);
		FD_SET(nfq_wf->exit_pipe[0], &rfds);

		/* wait for an incoming message on the netlink socket */
		retval = select(max_fd + 1, &rfds, NULL, NULL, &timeout);

		if (retval > 0) {
			if (FD_ISSET(fd, &rfds)) {
				DBG(5, " nf_sock fd %d set\n", fd);
// 				nl_recvmsgs_default(nfq_wf->nf_sock);
				__NfQueue_recv_pkt(nfq_wf);
			}

			if (FD_ISSET(nfq_wf->exit_pipe[0], &rfds)) {
				DBG(1," exit pipe %d set\n", nfq_wf->exit_pipe[0]);
			}
			timeout.tv_sec = 60;
			timeout.tv_usec = 0;
			timeout_pkt_count++;
		} else if (retval == 0) {
			DBG(5, " Timeout. Cleaning old connections\n");
			__httpConnList_expire(nfq_wf);
			timeout.tv_sec = 240;
			timeout.tv_usec = 0;
			timeout_pkt_count = 0;
		}

		// after 12345 packets processed force timeout check to free memory under heavy load
		if (timeout_pkt_count > 12345) {
			DBG(5, " Force expired connection check. Cleaning old connections\n");
			__httpConnList_expire(nfq_wf);
			timeout_pkt_count = 0;
		}
	}

	return NULL;
}

/**
* Create new NfQueue object
* @arg q_id   queue number that we will operate on
* @arg conf   configuration see @link WfConfig
*/
struct NfQueue* NfQueue_new(int q_id, struct WfConfig *conf)
{
	struct NfQueue *nfq_wf = NfQueue_alloc(&obj_ops);
	int ret;

	nfq_wf->q_id = q_id;
	WfConfig_get(conf);
	nfq_wf->config = conf;

	ret = pipe(nfq_wf->exit_pipe);
	if (ret) {
		DBG(1," Error opening pipe %d\n", ret);
	}

	return nfq_wf;
}



/** Start thread main loop
* @arg  Proxy object
* @return thread ID, or -errno
*/
int NfQueue_start(struct NfQueue* nfq_wf)
{
	int ret;
	nfq_wf->keep_running = true;

	ret = pthread_create(&nfq_wf->thread_id, NULL, __NfQueue_main, nfq_wf);

	return ret;
}

/**
* Tell the thread it should stop running
* @arg  Proxy object
* @return 0 if OK
*/
int NfQueue_stop(struct NfQueue* nfq_wf)
{
	int ret = 0xFEEDF00D;

	nfq_wf->keep_running = false;
	ret = write(nfq_wf->exit_pipe[1], &ret, sizeof(ret));
	if (ret < 0) {
		DBG(1," error writing to exit_pipe[1]=%d\n", nfq_wf->exit_pipe[1]);
	} else if (ret > 0) {
		DBG(1," wrote %d bytes to exit_pipe[1]=%d\n",ret, nfq_wf->exit_pipe[1]);
	}
	return 0;
}

/**
* block on pthread_join()
* @arg  Proxy object
* @return 0 if OK
*/
int NfQueue_join(struct NfQueue* nfq_wf)
{
	DBG(5, "Join proxy thread %p\n", nfq_wf);
	return pthread_join(nfq_wf->thread_id, NULL);
}

int NfQueue_updateConfig(struct NfQueue *nfq_wf, struct WfConfig *new_config)
{
	struct WfConfig *old_config;

	pthread_mutex_lock(&nfq_wf->config_mutex);
	old_config = nfq_wf->config;
	WfConfig_get(new_config);

	nfq_wf->config = new_config;

	WfConfig_put(&old_config);
	pthread_mutex_unlock(&nfq_wf->config_mutex);
	return 0;
}
/** @} */

