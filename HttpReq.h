#ifndef HTTP_REQ_H
#define HTTP_REQ_H 1

#include <linux/in.h>
#include <stdbool.h>
#include <ubiqx/ubi_dLinkList.h>

enum http_method { http_method_options, /* RFC 2616   sect 9.2 */
		http_method_get,         /* RFC 2616   sect 9.3 */
		http_method_head,
		http_method_post,
		http_method_put,
		http_method_delete,
		http_method_trace,
		http_method_connect };

struct ipv4_tcp_tuple {
	in_addr_t src_ip;
	in_addr_t dst_ip;
	in_port_t src_port; // 16 bit port
	in_port_t dst_port;
};

struct ipv4_tcp_pkt_node {
	ubi_dlNode node;	/** ubiqx "internal" data */
	struct ipv4_tcp_tuple tuple;
	uint16_t checksum;
	uint32_t seq_num;
	uint32_t ack_num;
	uint16_t packet_length; /// Length of IP packet
	uint16_t payload_length; /// Length of TCP payload
	void *data; /// pointer to raw IP packet data
	void *payload; /// pointer within data to TCP payload
};

typedef ubi_dlList ipv4_tcp_pkt_list_t;

struct HttpConn;
struct HttpReq_priv_data;

#define HTTP_REQ_MAX_CATEGORY_IDS 5

struct HttpReq {
	ubi_dlNode node;	/** ubiqx "internal" data */
	struct HttpConn *con; /* connection this request is a part of */
	unsigned request_id;  // an auto increment ID for us to track.
	enum http_method method;
	char *host;
	char *path;
	uint64_t content_length;  // expected length of data from server. 
	uint64_t read_content; // what we have already recieved
	ipv4_tcp_pkt_list_t *request_buffer; // Linked list of request data HTTP headers,  needed incase we have fragments of a single header.
	ipv4_tcp_pkt_list_t *response_buffer; // linked list of reponse packets, we only need HTTP headers


	/// NOTE  consider putting virus, phishing, malware, category, etc
	/// into some kind of atributes list,
	/// and each filter object can set the attributes it wants.
	bool virus;
	bool phishing;
	bool malware;
	int category_id[HTTP_REQ_MAX_CATEGORY_IDS];
	///
	
	struct HttpReq_priv_data **priv_data;
};

typedef ubi_dlList HttpReq_list_t;
struct ContentFilter;

struct HttpConn {
	ubi_dlNode node;	/** ubiqx "internal" data */
	uint8_t  tcp_state;
	int request_count;  // how many requests have been sent
	struct ipv4_tcp_tuple tuple;
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

struct HttpReq * HttpReq_new(struct HttpConn*);
void * HttpReq_new_priv_data_ptr(struct HttpReq *req, int key, void (*free_fn)(void *));

#endif