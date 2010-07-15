#ifndef HTTP_CONN_H
#define HTTP_CONN_H 1

#include <stdbool.h>
#include <time.h>
#include <ubiqx/ubi_dLinkList.h>
#include <linux/netfilter/nf_conntrack_tcp.h>

#include "HttpReq.h"

/**
* @defgroup HttpConn  HTTP connection
* @{
*/

struct ContentFilter;

typedef ubi_dlList ipv4_tcp_pkt_list_t;

struct HttpConn {
	ubi_dlNode node;	/** ubiqx "internal" data */
	uint32_t id;
	struct Ipv4TcpTuple tuple;
	uint32_t server_seq_num;  // note sure if this needed
	uint32_t server_ack_num;
	uint32_t client_seq_num;
	uint32_t client_ack_num;
	bool server_data_altered;
	bool not_http; /// true if we detect connection that does not comply with HTTP
	uint32_t packet_count;
	uint32_t request_count;  /// how many requests have been sent
	time_t last_pkt; ///time last packet received, used to remove stale connections
	unsigned cur_request; 
	unsigned cur_response;
	enum tcp_conntrack client_state;
	enum tcp_conntrack server_state;
	/// Contains pointer with reference to content filter and its rules
	struct WfConfig *config;

	struct PrivData *priv_data;

	/** linked list of HttpReq.  HTTP 1.1 persistent connections have multiple reqs per con.
	After request has been received by client we may remove from list.
	*/
	HttpReq_list_t *request_list;

	/** Linked list of packets from server, only used with out of order packets */
	ipv4_tcp_pkt_list_t *server_buffer;
	ipv4_tcp_pkt_list_t *client_buffer;
	
};


struct HttpConn* HttpConn_new(struct WfConfig *config);
void HttpConn_del(struct HttpConn **con);
int HttpConn_processsPkt(struct HttpConn* con, struct Ipv4TcpPkt *pkt);


typedef ubi_dlList HttpConn_list_t;


/** @}  */
#endif
