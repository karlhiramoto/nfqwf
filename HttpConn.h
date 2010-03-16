#ifndef HTTP_CONNH
#define HTTP_CONN_H 1

#include <stdbool.h>
#include <ubiqx/ubi_dLinkList.h>


/**
* @defgroup HttpConn  HTTP connection
* @{
*/

struct ContentFilter;

struct HttpConn {
	ubi_dlNode node;	/** ubiqx "internal" data */
	uint8_t  tcp_state;
	int request_count;  // how many requests have been sent
	struct Ipv4TcpTuple tuple;
	uint32_t server_seq_num;  // note sure if this needed
	uint32_t server_ack_num;
	uint32_t client_seq_num;
	uint32_t client_ack_num;

	/// Contains pointer with reference to content filter and its rules
// 	struct ContentFilter *c_filter;  
	
	/** linked list of HttpReq.  HTTP 1.1 persistent connections have multiple reqs per con.
	After request has been received by client we may remove from list.
	*/
	HttpReq_list_t *request_list;
	
};

typedef ubi_dlList HttpConn_list_t;


/** @}  */
#endif
