#define _GNU_SOURCE /* for memmem */
#include <stdlib.h>
#include <stdbool.h>
#include <pthread.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>

#ifdef HAVE_CONFIG_H
#include "nfq-web-filter-config.h"
#endif


#include "Ipv4Tcp.h"
#include "HttpConn.h"


#include "HttpReq.h"
#include "HttpConn.h"
#include "FilterList.h"
#include "Rules.h"
#include "ContentFilter.h"
#include "ProxyConfig.h"
#include "PrivData.h"
#include "nfq_proxy_private.h"

#define MAX(a, b) (a > b ? a : b)
#define MIN(a, b) (a < b ? a : b)



// NOTE not going to protect this auto increment ID sequence by a mutex.
// for now its only for debug, and only important that each HTTP connection
// has a unique ID per thread.   If another thread has the same ID
// on a different connection we don't care.
// anyways on most architectures increment should be atomic.
static uint32_t id_seq = 0;

static inline bool __pkt_from_server(struct Ipv4TcpPkt *pkt)
{
	return (pkt->tuple.src_port == HTTP_TCP_PORT);
}
static inline bool __pkt_from_client(struct Ipv4TcpPkt *pkt)
{
	return (pkt->tuple.dst_port == HTTP_TCP_PORT);
}

static struct HttpReq * __add_request_new_to_list(struct HttpConn *con)
{
	struct HttpReq *req = HttpReq_new(con);
	if (!req) {
		ERROR_FATAL("No memory for HttpReq\n");
	}

	ubi_dlAddHead(con->request_list, req);
	req->id = con->cur_request;

	return req;
}

static struct HttpReq * __find_request(struct HttpConn *con, unsigned id)
{
	struct HttpReq* req = NULL;
	
	/*for each object in list */
	for (req = (struct HttpReq *)ubi_dlFirst(con->request_list);
		req; req = (struct HttpReq *)ubi_dlNext(req)) {

		if (req->id == id)
			return req;
	}

	return NULL;
}


struct HttpConn* HttpConn_new(struct ProxyConfig *config)
{
	struct HttpConn *con;

	con = calloc(1, sizeof(struct HttpConn));
	if (!con)
		return NULL;

	con->request_list = malloc(sizeof(HttpReq_list_t));
	if (!con->request_list)
		goto free_con;
	con->request_list = ubi_dlInitList(con->request_list);
	
	con->server_buffer = malloc(sizeof(ipv4_tcp_pkt_list_t));
	if (!con->server_buffer)
		goto free_req_list;
	con->server_buffer = ubi_dlInitList(con->server_buffer);
	
	con->client_buffer = malloc(sizeof(ipv4_tcp_pkt_list_t));
	if (!con->client_buffer)
		goto free_server_buffer;
	con->client_buffer = ubi_dlInitList(con->client_buffer);


	con->priv_data = PrivData_new();

	con->client_state = TCP_CONNTRACK_NONE;
	con->server_state = TCP_CONNTRACK_NONE;
	con->id = ++id_seq;
	con->config = config;

	__add_request_new_to_list(con);

	return con;
	/* error cases */

	free_server_buffer:
	free(con->server_buffer);

	free_req_list:
	free(con->request_list);

	free_con:
	free(con);

	return NULL;
}

static void __pkt_list_free(ipv4_tcp_pkt_list_t *pkt_list)
{
	struct Ipv4TcpPkt *pkt;

	while ( (pkt = (struct Ipv4TcpPkt *) ubi_dlRemHead(pkt_list)) ) {
		DBG(1, "Warning freeing packet %p in buffer count=%lu\n",
			pkt, ubi_dlCount(pkt_list));
		Ipv4TcpPkt_del(&pkt);
	}
	free(pkt_list);
}
static void __pkt_list_insert(ipv4_tcp_pkt_list_t *pkt_list, struct Ipv4TcpPkt *pkt)
{
	struct Ipv4TcpPkt *next_pkt;
	struct Ipv4TcpPkt *cur_pkt = NULL;
	struct Ipv4TcpPkt *new_pkt;
	
	DBG(2, "Saving packet pkt->seq_num=%u list=%p count=%lu\n",
		pkt->seq_num, pkt_list, ubi_dlCount(pkt_list));
	next_pkt = (struct Ipv4TcpPkt *) ubi_dlFirst(pkt_list);
	while(next_pkt) {

		DBG(2, "cur_pkt->seq_num=%u pkt->seq_num=%u\n", next_pkt->seq_num, pkt->seq_num);
		if (pkt->seq_num < next_pkt->seq_num)
			break;
		cur_pkt = next_pkt;

		next_pkt = (struct Ipv4TcpPkt *) ubi_dlNext(cur_pkt);
	}

	// get a copy, because the original will be passed back to iptables/netfilter queue
	//TODO OPTIMIZE look into saving a reference count, and use the same packet without the copy
	new_pkt = Ipv4TcpPkt_clone(pkt);

	// if list is empty this will insert at head
	ubi_dlInsert(pkt_list, (ubi_dlNodePtr) new_pkt, (ubi_dlNodePtr) cur_pkt);
}

void HttpConn_del(struct HttpConn **con_in)
{
	struct HttpConn *con = *con_in;
	struct HttpReq* req;
	struct HttpReq* next_req = NULL;

	DBG(5, "Free http con %p id=%u\n", con, con->id);
	/*for each object in list */
	for (next_req = (struct HttpReq *)ubi_dlFirst(con->request_list);
		next_req; ) {

		req = next_req;
		next_req =  (struct HttpReq *)ubi_dlNext(req);
		DBG(5, "Free http req %p id=%d next=%p\n", req, req->id, next_req);
		HttpReq_del(&req);
		DBG(5, "Freed http req %p\n", req);
	
	}
	free (con->request_list);

	__pkt_list_free(con->server_buffer);
	__pkt_list_free(con->client_buffer);

	// free private data
	PrivData_del(&con->priv_data);
	
	free (con);
	*con_in = NULL;
}

int __HttpConn_checkFlags(struct HttpConn* con, struct Ipv4TcpPkt *pkt,
			enum tcp_conntrack cur_state)
{
	unsigned int tcp_flags_loc;
	enum tcp_conntrack next_tcp_state = cur_state;

	tcp_flags_loc = pkt->ip_hdr_len + TCP_FLAG_OFFSET;
	switch (cur_state) {
		case TCP_CONNTRACK_NONE:
			if (TCP_FLAG_SET(pkt, tcp_flags_loc, TCP_FLAG_SYN)) {
				next_tcp_state = TCP_CONNTRACK_SYN_SENT;
			}
		case TCP_CONNTRACK_SYN_SENT:
			if (TCP_FLAG_SET(pkt, tcp_flags_loc, TCP_FLAG_ACK)) {
				/* establised */
				next_tcp_state = TCP_CONNTRACK_ESTABLISHED;
			} else {
				DBG(1, "unknown state transition\n");
			}

			// when sever sends SYN ACK we know we're synchronized
			if (TCP_FLAG_SET(pkt, tcp_flags_loc, (TCP_FLAG_SYN | TCP_FLAG_ACK) )
				== (TCP_FLAG_SYN | TCP_FLAG_ACK)) {
				DBG(3, "TCP SYN/ACK seq=%u ack=%u\n", pkt->seq_num, pkt->ack_num);
				con->server_seq_num = con->client_ack_num = pkt->seq_num;
				con->client_seq_num = con->server_ack_num = pkt->ack_num;
			}

			break;
		case TCP_CONNTRACK_SYN_RECV:
		case TCP_CONNTRACK_ESTABLISHED:
			if ( TCP_FLAG_SET(pkt, tcp_flags_loc, TCP_FLAG_RST) ||
				TCP_FLAG_SET(pkt, tcp_flags_loc, TCP_FLAG_FIN)) {
				next_tcp_state = TCP_CONNTRACK_LAST_ACK;
			}
			break;
		case TCP_CONNTRACK_FIN_WAIT:
		case TCP_CONNTRACK_CLOSE_WAIT:
		case TCP_CONNTRACK_LAST_ACK:
			if (TCP_FLAG_SET(pkt, tcp_flags_loc, TCP_FLAG_ACK) || 
				TCP_FLAG_SET(pkt, tcp_flags_loc, TCP_FLAG_FIN) ||
				TCP_FLAG_SET(pkt, tcp_flags_loc, TCP_FLAG_RST)) {
				next_tcp_state = TCP_CONNTRACK_CLOSE;
			}
			break;
		case TCP_CONNTRACK_TIME_WAIT:
		case TCP_CONNTRACK_CLOSE:
			break;
		default:
			next_tcp_state = TCP_CONNTRACK_NONE;
			break;
	}

	DBG(3, "Current TCP state=%d ; next state=%d\n", cur_state, next_tcp_state);
	return next_tcp_state;
}

int __gen_error_packet(struct HttpReq *req, struct Ipv4TcpPkt *pkt,
		enum Action verdict)
{
	char *content = NULL;
	char *new_tcp_payload = NULL;
	int content_length;
	int tcp_payload_length;
	uint16_t new_pkt_size;
	uint16_t all_hdr_len;
	unsigned char *new_ip_pkt;
	uint16_t cksum;
	unsigned short *sptr;
	const char *reason = "Access denied";

	switch (verdict) {
		case Action_malware:
		case Action_virus:
			reason = "Malware or Virus";
			break;
		case Action_phishing:
			reason = "Phishing";
			break;
		default:
			reason = "Access denied";
			break;
	}

	content_length = asprintf(&content, "<html><head><title>Page Blocked</title></head>\n"
		"<body>\n"
		"<table border=\"0\" align=\"center\" cellspacing=\"20\">"
		"<tr><td>"
		"<font style=\"font-size:1.0em; font-family: Verdana, Arial, Geneva, Helvetica, sans-serif; color:#0B384E\" size=\"+2\">"
		"<b>Web Filter has blocked access to this page.</b></font>"
		"</td></tr>\n"
		"<tr><td>"
		"<font style=\"font-size:0.6em; font-family: Verdana, Arial, Geneva, Helvetica, sans-serif; color:#0B384E\">"
		"Reason: \"%s\".</font>"
		"</td></tr></table>\n"
		"</body></html>\r\n\r\n", reason);

	if (content_length < 1)
		return -ENOMEM;

	tcp_payload_length = asprintf(&new_tcp_payload, "HTTP/1.1 200 OK\r\n"
		"Content-Length: %d\r\n"
		"Content-Type: text/html\r\n"
		"Connection: close\r\n"
		"\r\n\r\n%s", content_length, content);

	free(content);
 	all_hdr_len = pkt->tcp_payload - pkt->ip_data;
	new_pkt_size = all_hdr_len + tcp_payload_length;
	DBG(5, "all_hdr_len=%d  new_pkt_size=%d tcp_payload_length=%d\n",
		all_hdr_len, new_pkt_size, tcp_payload_length);

	// have the client close this connection so we don't have to deal with tracking
	// modified sequence numbers
	Ipv4TcpPkt_setTcpFlag(pkt, TCP_FLAG_FIN);

	if (new_pkt_size > pkt->ip_packet_length) {
		DBG(6, "copy into NEW packet\n");
		new_ip_pkt = malloc(NLA_ALIGN(new_pkt_size));
		memcpy(new_ip_pkt, pkt->ip_data, all_hdr_len);
		memcpy(&new_ip_pkt[all_hdr_len], new_tcp_payload, tcp_payload_length);
	} else {
		DBG(6, "copy into OLD packet\n");
		new_ip_pkt = pkt->ip_data;
		memcpy(pkt->tcp_payload, new_tcp_payload, tcp_payload_length);
	}
	free(new_tcp_payload);

	DBG(4, "IP: DS=0x%02hhx ID=%u=0x%hx flags=0x%x Frag_Offset=0x%x TTL=%d proto=%d\n",
		new_ip_pkt[1],
		ntohs((uint16_t) *((uint16_t*) &new_ip_pkt[4])),
		ntohs((uint16_t) *((uint16_t*) &new_ip_pkt[4])),
		(new_ip_pkt[6] >> 4),
		ntohs((uint16_t) *((uint16_t*) &new_ip_pkt[6])) & 0x0FFF,
		new_ip_pkt[8], new_ip_pkt[9]);

 	sptr = (unsigned short *) &new_ip_pkt[2];  // IP Packet size
 	*sptr = htons(new_pkt_size); // set new size

	DBG(6, "new_pkt_size=%d sptr=0x%hx\n", new_pkt_size, *sptr);		

	sptr = (unsigned short *) &new_ip_pkt[10];  // IP header checksum8
	*sptr = 0;
	cksum = get_cksum16((unsigned short *)new_ip_pkt, pkt->ip_hdr_len, 0);
	*sptr = cksum;

	Ipv4TcpPkt_resetTcpCksum(new_ip_pkt, new_pkt_size, pkt->ip_hdr_len);

	DBG(5, "new calc cksum=%hu=0x%04hx new_pkt_size=%d pkt->ip_hdr_len=%d\n", cksum, cksum, new_pkt_size, pkt->ip_hdr_len);

	pkt->modified_ip_data = new_ip_pkt;
	pkt->modified_ip_data_len = new_pkt_size;

#if 0
// for debug only,   NOTE  if pkt->ip_data == modified_ip_data we will not free
	pkt->ip_data = new_ip_pkt;
	pkt->ip_packet_length = new_pkt_size;
	// for debug and to recheck checksum
	Ipv4TcpPkt_parseIpPayload(pkt);
#endif

// // 	Ipv4TcpPkt_printPkt(pkt, stdout);
// 	print_hex(new_ip_pkt, new_pkt_size);

	req->con->server_data_altered = true;
	req->con->server_seq_num = pkt->seq_num + pkt->modified_ip_data_len;
	req->con->server_ack_num = pkt->ack_num;
	return 0;
}

#if 0
static int __get_next_line(char **lineptr, char *start, unsigned int *len)
{
	char *p = start;
	unsigned int n = *len;
	int count;

	*lineptr = start; // init

	if (n > 65535) {
		ERROR_FATAL("length invalid %u\n", n);
	}

	// find end of this line
	while (*p != '\r' && *p != '\n' && n != 0) {
		p++;
		n--;
	}

	*len = n;
	
	// if reached end of line but no more data 
	if (n < 2) {
		// if we ran out of buffer to parse
		if (n == 0) {
			count = ZERO_EOL;
			goto out;
		}

		count = ONE_EOL;
		goto out;
	}
	// at this point there is at least one EOL p points to a \r or \n

	// There are now several cases we want to check
	//  Case 0    \r\n    One EOL
	//  Case     \n    One EOL
	//  Case     \r    One EOL
	//  Case     \r\n\r\n    TWO
	//  Case     \n\r\n    TWO
	//  Case     \n\n    TWO

	if (*p == '\n') {
		count = 1;
	} else {
		count = 0;
	}

	while ( (*p == '\r' || *p == '\n') && (n != 0) && count < 2 )  {
		p++;
		n--;
		if (*p == '\n') {
			count++;
		}
	}
	DBG(6, "p=0x%hhx='%c' start='%c' count=%d n=%d\n", *p, *p, *start, count, n);
	if (*p == '\n' && count == 2 && n != 0) {
		// advance off end of line
		p++;
		n--;
	}
	
	out:
	*lineptr = p;
	*len = n;
	return count;
}
#endif

static void __handle_non_http_pkt(struct HttpConn* con, struct Ipv4TcpPkt *pkt)
{
	enum non_http_action action;

	action = ProxyConfig_getNonHttpAction(con->config);
	DBG(4, "non HTTP action=%d payload len=%d\n", action,  pkt->tcp_payload_length);

	switch (action) {
		case non_http_action_accept:
			// NF verdict Already accept by default
			break;
		case non_http_action_drop:
			DBG(4, "drop packet\n");
			Ipv4TcpPkt_setNlVerictDrop(pkt);
			break;
		case non_http_action_reset:
		default:
			if (pkt->tcp_payload_length) {
				memset(pkt->tcp_payload, '\n', pkt->tcp_payload_length);
// 				Ipv4TcpPkt_resetTcpCksum(pkt->ip_data, pkt->ip_packet_length, pkt->ip_hdr_len);
// 				pkt->modified_ip_data = pkt->ip_data; // mark modified
			}
			// if not already closing
// 			if (MIN(con->server_state, con->client_state) < TCP_CONNTRACK_CLOSE_WAIT
// 				&& !TCP_FLAG_SET(pkt, pkt->ip_hdr_len + TCP_FLAG_OFFSET,
// 				(TCP_FLAG_FIN) )) {

				DBG(4, "reset connection\n");
				Ipv4TcpPkt_setTcpFlag(pkt, (TCP_FLAG_RST)); // set RST

				Ipv4TcpPkt_resetTcpCksum(pkt->ip_data, pkt->ip_packet_length, pkt->ip_hdr_len);
				pkt->modified_ip_data = pkt->ip_data; // mark modified
				Ipv4TcpPkt_resetTcpCon(pkt);
				con->server_data_altered = true;
// 			}
			break;
	}
}


static int __processs_req_payload(struct HttpConn* con, struct Ipv4TcpPkt *pkt)
{
	struct HttpReq *req;
	unsigned char *p;
	unsigned char *end;
	unsigned char *line = NULL;
	unsigned len;
	unsigned int str_len;
	int ret;
	struct http_msg *msg;
// 	char value_str[16];  // for parsing numbers

	DBG(5, "process http request cur_request=%d\n", con->cur_request);
	req = __find_request(con, con->cur_request);
	if (!req) {
		DBG(5, "request not found allocate new\n");
		req = __add_request_new_to_list(con);
	}
	msg = &req->client_req_msg;
	DBG(5, "http request id=%d state=%d\n", req->id, req->client_req_msg.state);
	len = pkt->tcp_payload_length;
	p = (unsigned char*) pkt->tcp_payload;
	
	switch (msg->state) {
		case msg_state_new:
			DBG(5, "Processing new request packet\n");
			if (pkt->tcp_payload_length < 5)  {
				// Not posssible to "GET /\n" in less than 5 chars 
				req->client_req_msg.state = msg_state_partial;
				break;
			}

			// to check begining of packet for GET/POST/PUT/OPTOINS
			len = MIN(pkt->tcp_payload_length, 15);

			if ( (p = memmem(pkt->tcp_payload, len, "GET ", 4)) ) {
				req->method = http_method_get; /* RFC 2616   sect 9.3 */
				DBG(4, "HTTP method GET\n");
			} else if ( (p = memmem(pkt->tcp_payload, len, "OPTIONS ", 8)) ) {
				req->method = http_method_options; /* RFC 2616   sect 9.2 */
				DBG(4, "HTTP method OPTIONS\n");
			} else if ( (p = memmem(pkt->tcp_payload, len, "HEAD ", 5)) ) {
				/* HEAD response will not have any message body RFC 2616 Sect 9.4*/
				req->method = http_method_head;
				DBG(4, "HTTP method HEAD\n");
			} else if ( (p = memmem(pkt->tcp_payload, len, "POST ", 5)) ) {
				req->method = http_method_post;
				DBG(4, "HTTP method POST\n");
			} else if ( (p = memmem(pkt->tcp_payload, len, "PUT ", 4)) ) {
				req->method = http_method_put;
				DBG(4, "HTTP method PUT\n");
			} else if ( (p = memmem(pkt->tcp_payload, len, "DELETE ", 6)) ) {
				req->method = http_method_delete;
				DBG(4, "HTTP method DELETE\n");
			} else if ( (p = memmem(pkt->tcp_payload, len, "TRACE ", 6)) ) {
				req->method = http_method_trace;
				DBG(4, "HTTP method TRACE\n");
			} else if ( (p = memmem(pkt->tcp_payload, len, "CONNECT ", 5)) ) {
				req->method = http_method_connect;
				DBG(4, "HTTP method CONNECT\n");
			} else if ( (p = memmem(pkt->tcp_payload, len, "PROPFIND ", 8)) ) {
				req->method = http_method_propfind;
				DBG(4, "HTTP method PROPFIND\n");
			} else if ( (p = memmem(pkt->tcp_payload, len, "PROPPATCH ", 9)) ) {
				req->method = http_method_proppatch;
				DBG(4, "HTTP method PROPPATCH\n");
			} else if ( (p = memmem(pkt->tcp_payload, len, "COPY ", 5)) ) {
				req->method = http_method_copy;
				DBG(4, "HTTP method COPY\n");
			} else if ( (p = memmem(pkt->tcp_payload, len, "MOVE ", 5)) ) {
				req->method = http_method_move;
				DBG(4, "HTTP method MOVE\n");
			} else if ( (p = memmem(pkt->tcp_payload, len, "LOCK ", 5)) ) {
				req->method = http_method_lock;
				DBG(4, "HTTP method LOCK\n");
			} else if ( (p = memmem(pkt->tcp_payload, len, "UNLOCK ", 7)) ) {
				req->method = http_method_unlock;
				DBG(4, "HTTP method UNLOCK\n");
			} else if ( (p = memmem(pkt->tcp_payload, len, "REPORT ", 6)) ) {
				req->method = http_method_report;
				DBG(4, "HTTP method REPORT\n");
			} else if ( (p = memmem(pkt->tcp_payload, len, "VERSION-CONTROL  ", 15)) ) {
				req->method = http_method_version_control;
				DBG(4, "HTTP method VERSION-CONTROL\n");
			} else if ( (p = memmem(pkt->tcp_payload, len, "CHECKOUT ", 9)) ) {
				req->method = http_method_checkout;
				DBG(4, "HTTP method CHECKOUT\n");
			} else if ( (p = memmem(pkt->tcp_payload, len, "CHECKIN  ", 8)) ) {
				req->method = http_method_checkin;
				DBG(4, "HTTP method CHECKIN\n");
			} else if ( (p = memmem(pkt->tcp_payload, len, "UNCHECKOUT ", 11)) ) {
				req->method = http_method_uncheckout;
				DBG(4, "HTTP method UNCHECKOUT\n");
			} else if ( (p = memmem(pkt->tcp_payload, len, "MKWORKSPACE ", 11)) ) {
				req->method = http_method_mkworkspace;
				DBG(4, "HTTP method MKWORKSPACE\n");
			} else {
				msg->state = msg_state_partial;
				DBG(4, "HTTP method not detected\n");
			}

			if (!p) {
				//TODO ignore invalid HTTP
				WARN(" Invalid HTTP \n");
				con->not_http = true;
				__handle_non_http_pkt(con, pkt);
				return 0;
			}
			p += 4; // 'GET ' is shortest
			len = pkt->tcp_payload_length-4;

			// advance past any extra white space
			while ((*p == ' ' || *p == '\t') && len > 0) {
				p++;
				len--;
			}
			// now should be at the beginning of the GET/POST/PUT path
			end = p;
			while ((*end > ' ' && *end < 127) && len > 0) {
				end++;
				len--;
			}
			str_len = end-p;
			DBG(4, "GET/POST request path len=%d remaining=%d\n", str_len, len);
			req->path = malloc(str_len+1);
			memcpy(req->path, p, str_len);
			req->path[str_len] = 0; /* NULL term */
			DBG(4, "REQEUEST path='%s'\n", req->path);
			while ((*end <= ' ' || *end > 126) && len > 0) {
				if (*end == '\n') {
					// If CRLFCRLF then end of request
					if ( (len > 2 && (*(end+2) == '\n')) ||
						(len > 1 && (*(end+1) == '\n')) ) {
						goto request_complete;
					}
				}
				end++;
				len--;
			}
			p = end;
		// Fall through
		case msg_state_partial:

			// check if we have left over data from previous packet to parse
			if (unlikely(msg->buf_line != NULL)) {
				DBG(6, "Data from previous packet to parse %d bytes \n", msg->buf_line_len);

				end = p;
				// advance to end of line
				for (str_len = 0; len && (*end != '\r' && *end != '\n') ; ) {
					len--; // consume current packet
					end++;
					str_len++;
				}

				// include end of line markers
				while (len && (*end == '\r' || *end == '\n')) {
					len--; // consume current packet
					end++;
					str_len++;
				}

				DBG(6, " %d bytes from this packet and %d bytes from previous \n",
					str_len, msg->buf_line_len);

				// alloc line buffer to be size of previous part and current line
				line = malloc(msg->buf_line_len + str_len);
				if (unlikely(!line)) {
					ERROR_FATAL("Out of memory\n");
				}
				// copy old data into buffer
				memcpy(line, msg->buf_line, msg->buf_line_len);
				// copy new data into buffer
				memcpy(&line[msg->buf_line_len], p, str_len);

				str_len += msg->buf_line_len;

				// cleanup incase this data is part of a fragment and
				// HttpReq_processHeaderLine() will need to save another partial packet
				free(msg->buf_line);
				msg->buf_line = NULL; // NULL to mark unused
				msg->buf_line_len = 0;
				p = end; // update p, this is where we will later continue at
				end = line;  // tmp pointer so we don't loose ours, to later free line
				ret = HttpReq_processHeaderLine(req, true, &end, &str_len);
				free(line);

				// if end of current request
				if (ret == TWO_EOL) {
					DBG(7, "End of request found that spanned two packets\n");
					goto two_eol_found;
				}
			}

			DBG(7, "p=0x%hhx len=%d\n", *p, len);
#if 0
			if (*p != '\n'&& *p != '\r' && len > 0)  {
				ret = HttpReq_processHeaderLine(req, true, &p, &len);

				if (ret == TWO_EOL) {
					DBG(7, "End of request in packet with only one header line\n");
					goto two_eol_found;
				}
			}
#endif
			while ( (ret = HttpReq_processHeaderLine(req, true, &p, &len)) == ONE_EOL && len > 0) {
				// Processing request line by line
			}

			DBG(5, "no more lines ret=%d len=%d\n", ret, len);
			
			two_eol_found:
			if (ret == TWO_EOL) {
				DBG(3, "CRLFCRLF request headers complete len=%d req_len=%llu\n", len, msg->content_length);
				if (msg->content_length) {
					msg->content_received +=len;
					msg->state = msg_state_read_content;

					if (msg->content_received >= msg->content_length) {
						DBG(5, "POST/PUT/OPTIONS request content finished received=%llu Content-length=%llu\n",
							msg->content_received, msg->content_length);
						
						goto request_complete;
					}
					break;
				}
				goto request_complete;
			} else if (ret == ONE_EOL) {
				// NOTE there is a small possibility that the CRLFCRLF is fragmented across two packets

				DBG(5, "Ending on one EOL p=%p line=%p msg->buf_line=%p len=%d \n",
					p, line, msg->buf_line, len);
				if (!len)
					p--; // backup one space
				DBG(5, "Ending on one EOL p=0x%hhx\n", *p);

				if (len < 3 && msg->buf_line == NULL
					&& pkt->tcp_payload_length > 2 && (*p == '\r'|| *p == '\n')) {

					DBG(5, "save one EOL to buffer\n");
					msg->buf_line = malloc(4);
					str_len = 0;

					do {
						msg->buf_line[str_len] = *p;
						p--;
						str_len++;
					} while (str_len < 4 && (*p == '\r'|| *p == '\n'));

					msg->buf_line_len = str_len;
				}
				DBG(5, "saved %d Req bytes\n", str_len);
			}

			DBG(3, "request partial ret=%d\n", ret);
			msg->state = msg_state_partial;

			break;

		case msg_state_read_content:
			msg->content_received += pkt->tcp_payload_length;

			DBG(5, "Post/Put received=%llu Content-length=%llu\n",
				msg->content_received, msg->content_length);
			
			if (msg->content_received >= msg->content_length) {
				DBG(5, "POST/PUT request content finished\n");
				
				goto request_complete;
			}
			break;
		case msg_state_complete:
			DBG(5, "WTF Process completed request\n");

		default:
			ERROR_FATAL("Invalid request state =%d \n", msg->state);
			break;
	}

	DBG(5, "return request id=%d state=%d method=%d\n", req->id, msg->state, req->method);
	return 0;
	
	request_complete:

	msg->state = msg_state_complete;
	con->cur_request++;
	if (!req->path) {
		ERROR_FATAL("BUG parsing URL Path\n");
	}
	if (!strncmp(req->path,"http://",7)) {
		req->url = strdup(req->path);
	} else {
		if (req->path[0] == '/')
			ret = asprintf(&req->url,"http://%s%s", req->host, req->path);
		else
			ret = asprintf(&req->url,"http://%s/%s", req->host, req->path);
		if (ret == -1) {
			ERROR_FATAL("asprintf failed!\n");
		}
	}

	DBG(2, "path='%s' host='%s' url='%s'\n", req->path, req->host, req->url);
	ContentFilter_requestStart(req->cf, req);
	return 0;
}

/* FIXME BUG
RFC2616  "Transfer-encoding: chunked" is not handled properly,
and we only detect end of transfer when connection closes. Not a crash bug,
but prevents blocking request numbers+1 on the same connections
*/
static int __processs_response_payload(struct HttpConn* con, struct Ipv4TcpPkt *pkt)
{
	struct HttpReq *req;
	unsigned int len;
	char value_str[16];
	unsigned char *p;
	unsigned char *end;
	enum Action verdict;
	int ret;
	unsigned char *line = NULL;
	unsigned int str_len;
	struct http_msg *msg;
	
	DBG(5, "process http response cur_response= %d\n", con->cur_response);
	req = __find_request(con, con->cur_response);
	if (!req) {
		DBG(5, "request/response not found allocate new\n");
 		req =__add_request_new_to_list(con);
	} else {
		DBG(5, "http response id=%d content_received=%llu content_length=%llu\n",
			req->id, req->server_resp_msg.content_received, req->server_resp_msg.content_length);
	}
 	p = (unsigned char*) pkt->tcp_payload;
 	len = pkt->tcp_payload_length;
	msg = &req->server_resp_msg;

	switch (msg->state) {
		case msg_state_new:
			// can only be new once
			msg->state = msg_state_partial;

			if (len < 8 || memcmp( p , "HTTP/", MIN(5, len))) {
				// NOTE this happens when on a http server when over loaded it may send a Overload without http headers
				WARN("Not HTTP protocol len=%d HTTP missing. FIXME ignore this packet/connection\n", len);
				con->not_http = true;
				__handle_non_http_pkt(con, pkt);
				return 0;
			}
			p += 5; // Skip past "HTTP/"
			len -= 5;
			// advance to space before code
			while ( (*p != ' ' && *p!= '\n') && len > 0) {
				p++;
				len--;
			}
			// skip past space
			while ( *p == ' ' && len > 0) {
				p++;
				len--;
			}

			// this memcpy should normall copy responces code XXX\r
			memcpy(value_str, p, MIN(4, len));
			value_str[4] = 0; // null term
			req->resp_status_code = strtol(value_str, NULL, 10);
			DBG(5, "HTTP response status code = %u\n", req->resp_status_code);

		// fall through
		case msg_state_partial:
#if 0
			while ( (ret = __get_next_line(&line, p, &len)) == ONE_EOL && len > 0) {
				char test[16];
				memcpy(test, line, MIN(len, sizeof(test)-1));
				test[MIN(len, sizeof(test)-1)] = 0;
				DBG(6, "read line='%s' remaining len=%d\n", test, len)

				if (!msg->content_length &&
					(p = memmem(line, MIN(len, 16), "Content-Length: ", 16))) {
						// with POST/PUT requests there will be content length data part of the POST/PUT
					p += 16;
					len -= 16;
					while (!isdigit(*p) && len > 0) {
						p++;
						len--;
					}
					end = p;
					// should now be positioned on 1st digit
					while (isdigit(*end) && len > 0) {
						end++;
						len--;
					}
					if (!len) {
						msg->state = msg_state_partial;
						DBG(1, "Partial request\n");
						ERROR_FATAL("FIXME partial request\n");
					}

					// set len to be string length of content-length number
					str_len = end - p;
					if (str_len > 15) {
						ERROR_FATAL("Bug parsing content-length\n");
					}
					memcpy(value_str, p, str_len);
					value_str[str_len] = 0; // NULL term
					msg->content_length = strtoull(value_str, NULL, 0);
					
					DBG(3, "Content length = %llu len=%d\n", msg->content_length, len);
					p = end;  // continue at end of number,  len is already updated.
				} else if (!msg->content_length &&
					(p = memmem(line, MIN(len, 11), "Location: ", 10))) {
					
					p += 10;
					len -= 10;
					DBG(3, "Goto new location, response done\n");

				} else {
					// just advance to next line
					p = line;
				}
			} // while each line

			if (ret == TWO_EOL) {
				DBG(3, "CRLF response headers complete len=%d\n", len);
				msg->state = msg_state_read_content;
				goto response_hdr_complete;
			}
			msg->state = msg_state_partial;
#endif
			// check if we have left over data from previous packet to parse
			if (unlikely(msg->buf_line != NULL)) {
				DBG(6, "Data from previous packet to parse %d bytes \n", msg->buf_line_len);

				end = p;
				// advance to end of line
				for (str_len = 0; len && (*end != '\r' && *end != '\n') ; ) {
					len--; // consume current packet
					end++;
					str_len++;
				}

				// include end of line markers
				while (len && (*end == '\r' || *end == '\n')) {
					len--; // consume current packet
					end++;
					str_len++;
				}

				DBG(6, " %d bytes from this packet and %d bytes from previous \n",
					str_len, msg->buf_line_len);

					// alloc line buffer to be size of previous part and current line
					line = malloc(msg->buf_line_len + str_len);
					if (unlikely(!line)) {
						ERROR_FATAL("Out of memory\n");
					}
					// copy old data into buffer
					memcpy(line, msg->buf_line, msg->buf_line_len);
					// copy new data into buffer
					memcpy(&line[msg->buf_line_len], p, str_len);

					str_len += msg->buf_line_len;

					// cleanup incase this data is part of a fragment and
					// HttpReq_processHeaderLine() will need to save another partial packet
					free(msg->buf_line);
					msg->buf_line = NULL; // NULL to mark unused
					msg->buf_line_len = 0;
					p = end; // update p, this is where we will later continue at
					end = line;  // tmp pointer so we don't loose ours, to later free line
					ret = HttpReq_processHeaderLine(req, false, &end, &str_len);
					free(line);

					// if end of current request
					if (ret == TWO_EOL) {
						DBG(7, "End of request found that spanned two packets\n");
						goto two_eol_found;
					}
			}

			DBG(7, "p=0x%hhx len=%d\n", *p, len);

			while ( (ret = HttpReq_processHeaderLine(req, false, &p, &len)) == ONE_EOL && len > 0) {
				// Processing request line by line
			}

			DBG(5, "no more lines ret=%d len=%d\n", ret, len);

			two_eol_found:
			if (ret == TWO_EOL) {
				DBG(3, "CRLFCRLF response headers complete len=%d req_len=%llu recieved=%lld\n",
					len, msg->content_length, msg->content_received);
#if 0
				if (msg->content_length) {
					msg->content_received += len;
					
					// +1 because is remaining length and must include this byte
/*					if (len)
						msg->content_received++;*/
					
					msg->state = msg_state_read_content;

					if (msg->content_received >= msg->content_length) {
						DBG(5, "POST/PUT/OPTIONS request content finished received=%llu Content-length=%llu\n",
							msg->content_received, msg->content_length);

							goto response_hdr_complete;
					}
					break;
				} else if (msg->chunked) {

					msg->state = msg_state_read_content;
				}
#endif
				goto response_hdr_complete;
			} else if (ret == ONE_EOL) {
				// NOTE there is a small possibility that the CRLFCRLF is fragmented across two packets

				DBG(5, "Ending on one EOL p=%p line=%p msg->buf_line=%p len=%d \n",
					p, line, msg->buf_line, len);
					if (!len)
						p--; // backup one space
						DBG(5, "Ending on one EOL p=0x%hhx\n", *p);

					if (len < 3 && msg->buf_line == NULL
						&& pkt->tcp_payload_length > 2 && (*p == '\r'|| *p == '\n')) {

							DBG(5, "save one EOL to buffer\n");
							msg->buf_line = malloc(4);
							str_len = 0;

							do {
								msg->buf_line[str_len] = *p;
								p--;
								str_len++;
							} while (str_len < 4 && (*p == '\r'|| *p == '\n'));

							msg->buf_line_len = str_len;
						}
						DBG(5, "saved %d Req bytes\n", str_len);
			}

			DBG(3, "request partial ret=%d\n", ret);
			msg->state = msg_state_partial;
		break;

		case msg_state_read_content:
			DBG(1, "Recieving  msg_state_read_content\n");
			HttpReq_consumeResponseContent(req, p, len);

			//FIXME  if the payload is more than the content length, the may contain another request. 

		break;
		case msg_state_complete:
			DBG(1, "FIXME TODO\n");
			break;
		default:
			ERROR_FATAL("invalid state\n");
		break;
	}


	return 0;

	response_hdr_complete:

	verdict = HttpReq_consumeResponseContent(req, p, len);

	if (verdict && (Action_malware | Action_reject | Action_virus | Action_phishing)){
		DBG(3, "Generate error msg for bad content\n");
		__gen_error_packet(req, pkt, verdict);
		return 0;
	}

	// NOTE not going to check verdict on:
	// HTTP 204 No content timeout, the server may send this without a request
	// HTTP 408 HTTP/1.0 408 Request Time-out 207.123.63.126 will do this
	
	if ((req->resp_status_code != 204)
		&& (req->resp_status_code != 408) // timeout
		&& (req->resp_status_code != 400) // bad request
		&& req->method != http_method_head) {
		// check verdict
		verdict = ContentFilter_getRequestVerdict(req->cf, req);
		DBG(3, "verdict = 0x%x len=%d content_received=%lld\n",
			verdict, len, msg->content_received);

		switch (verdict) {
			case Action_reject:
			case Action_virus:
				DBG(3, "Generate error msg\n");
				__gen_error_packet(req, pkt, verdict);
				break;
			default:
				break;
		}
	}

	// RFC2616 status codes 204 and 304 have no message body
	if (req->resp_status_code == 204 || req->resp_status_code == 304 ||
		req->resp_status_code == 400 ||
		req->method == http_method_head) {
		// response codes that have no message body
		DBG(5, "Http message code %u with no body\n", req->resp_status_code);
		req->con->cur_response++;
		msg->state = msg_state_complete;
	}



	return 0;
}

static int __processs_pkt_payload(struct HttpConn* con, struct Ipv4TcpPkt *pkt)
{
	int ret = 0;

	DBG(5, "cur_request=%d response=%d\n",
		con->cur_request, con->cur_response);

	if (__pkt_from_client(pkt)) {
		if (con->server_data_altered) {
			// adjust client ACK number
			pkt->ack_num = htonl(con->client_seq_num);
			con->server_seq_num += pkt->tcp_payload_length;
			DBG(5, "Change client ack to %d\n", ntohl(pkt->ack_num));
			memcpy(&pkt->ip_data[pkt->ip_hdr_len+8],&pkt->ack_num, sizeof(int));

			Ipv4TcpPkt_resetTcpCon(pkt);
		} else {
			ret = __processs_req_payload(con, pkt);
		}
		
	} else if (__pkt_from_server(pkt)) {
		if (con->server_data_altered) {
			// adjust client ACK number
			pkt->ack_num = htonl(con->server_seq_num);
			con->server_seq_num += pkt->tcp_payload_length;
			DBG(5, "Change server/client ack to %d\n", ntohl(pkt->ack_num));
			memcpy(&pkt->ip_data[pkt->ip_hdr_len+8],&pkt->ack_num, sizeof(int));
			Ipv4TcpPkt_resetTcpCon(pkt);
		} else {
			ret = __processs_response_payload(con, pkt);
		}
	} else {
		ERROR_FATAL("Invalid packet not from client or server. broken. \n");
		return -EINVAL;
	}
	return 0;
}

static int __pkt_list_process(struct HttpConn* con, ipv4_tcp_pkt_list_t *pkt_list)
{
	struct Ipv4TcpPkt *next_pkt;
// 	struct Ipv4TcpPkt *cur_pkt = NULL;
	int ret = 0;
	
	
	next_pkt = (struct Ipv4TcpPkt *) ubi_dlRemHead(pkt_list);
	if (next_pkt) {
		DBG(2, "Extracted saved packet from list count=%lu\n", ubi_dlCount(pkt_list));
		ret = HttpConn_processsPkt(con, next_pkt);
		Ipv4TcpPkt_del(&next_pkt); // delete packet as we are done with it.		
	}

	return ret;
}


int HttpConn_processsPkt(struct HttpConn* con, struct Ipv4TcpPkt *pkt)
{
	int delta;
	con->last_pkt = time(NULL);
	int min_state;

	// if no connection associated with this packet
	if (con->server_state == TCP_CONNTRACK_NONE) {
		// setup so destination is http server
		if (__pkt_from_server(pkt)) {
			/* swap so dst port is http */
			con->tuple.src_port = pkt->tuple.dst_port;
			con->tuple.dst_port = pkt->tuple.src_port;
			con->tuple.src_ip = pkt->tuple.dst_ip;
			con->tuple.dst_ip = pkt->tuple.src_ip;
			con->server_seq_num = pkt->seq_num;
			con->server_ack_num = pkt->ack_num;
		} else {
			memcpy(&con->tuple, &pkt->tuple, sizeof(struct Ipv4TcpTuple));
			con->client_seq_num = pkt->seq_num;
			con->client_ack_num = pkt->ack_num;
		}
	}
	if (unlikely(con->not_http)) {
		DBG(1, " Non HTTP connection\n");
		if (__pkt_from_server(pkt)) {
			con->server_state = __HttpConn_checkFlags(con, pkt, con->server_state);
		} else {
			con->client_state = __HttpConn_checkFlags(con, pkt, con->client_state);
		}

		__handle_non_http_pkt(con, pkt);

		min_state = MIN(con->server_state, con->client_state);

		// if safe to close and cleanup memory
		if (min_state > TCP_CONNTRACK_CLOSE_WAIT &&
			MAX(con->server_state, con->client_state) == TCP_CONNTRACK_CLOSE)
			return TCP_CONNTRACK_CLOSE;

		return min_state;
	}

	if (__pkt_from_server(pkt)) {
		delta = (int) (pkt->seq_num - con->server_seq_num);
		DBG(5, "Pkt from server  server_seq_num=%u  pkt_seq_num=%u delta=%d\n",
			con->server_seq_num, pkt->seq_num, delta);
		
		if (pkt->tcp_payload_length) {

			//if packet already seen
			if (delta < 0
				&& (con->server_seq_num < TCP_SEQ_HI_WRAPZONE)) {
				DBG(1, "repeated or duplicate packet seq_num=%u server_seq_num=%u\n", pkt->seq_num, con->server_seq_num);
				return MIN(con->server_state, con->client_state);
			} else if (delta > 1) {
				DBG(1, "Save packet from server\n");
				__pkt_list_insert(con->server_buffer, pkt);
				return -EBUSY;
				
			} else {
				con->server_seq_num = pkt->seq_num + pkt->tcp_payload_length;
				con->server_ack_num = pkt->ack_num;
				__processs_pkt_payload(con, pkt);

			}
		}
	
		DBG(5, "Pkt from server  server_seq_num=%u  pkt_seq_num=%u delta=%d\n",
		con->server_seq_num, pkt->seq_num, delta);
	
		// process any out of order packets that come after current pkt
		__pkt_list_process(con, con->server_buffer);

		con->server_state = __HttpConn_checkFlags(con, pkt, con->server_state);


	} else {
		delta = (int) (pkt->seq_num - con->client_seq_num);
		DBG(5, "Pkt from client  client_seq_num=%u  pkt_seq_num=%u delta=%d\n"
		, con->client_seq_num, pkt->seq_num, delta);
		if (pkt->tcp_payload_length) {
		
			//if packet already seen
			if (delta < 0
				&& (con->client_seq_num < TCP_SEQ_HI_WRAPZONE)) {
				DBG(1, "repeated or duplicate packet pkt->seq_num=%u con->client_seq_num=%u\n", pkt->seq_num, con->client_seq_num);
				return MIN(con->server_state, con->client_state);
			} else if (delta > 1) {
				DBG(1, "Save packet from client\n");
				__pkt_list_insert(con->client_buffer, pkt);
				return -EBUSY;
			} else {
				con->client_seq_num = pkt->seq_num + pkt->tcp_payload_length;
				con->client_ack_num = pkt->ack_num;
				__processs_pkt_payload(con, pkt);
			}
		}
		DBG(5, "Pkt from client  client_seq_num=%u  pkt_seq_num=%u delta=%d\n"
		, con->client_seq_num, pkt->seq_num, delta);
		con->client_state = __HttpConn_checkFlags(con, pkt, con->client_state);
		// process any out of order packets that come after this one
		__pkt_list_process(con, con->client_buffer);
	}

DBG(5, " Server state=%d ; client state = %d  client_seq_num= %u server_seq_num= %u\n",
	con->server_state, con->client_state,  con->client_seq_num, con->server_seq_num);
#if 0	
	if (pkt->tcp_payload_length) {
		if (con->server_data_altered) {
// 			Ipv4TcpPkt_setTcpFlag(pkt, TCP_FLAG_RST); // set FIN
// 			Ipv4TcpPkt_clearTcpFlag(pkt, TCP_FLAG_PSH); // clear data flag
// 			Ipv4TcpPkt_resetTcpCksum(pkt->ip_data, pkt->ip_packet_length, pkt->ip_hdr_len);
// 			pkt->modified_ip_data = pkt->ip_data; // mark modified
		} else
			__processs_pkt_payload(con, pkt);
	} else {
		DBG(5, " skip process packet. no payload \n");
	}
#endif
	
	min_state = MIN(con->server_state, con->client_state);

	// if safe to close and cleanup memory
	if (min_state > TCP_CONNTRACK_CLOSE_WAIT &&
		MAX(con->server_state, con->client_state) == TCP_CONNTRACK_CLOSE)
		return TCP_CONNTRACK_CLOSE;

	return min_state;
}

#if 0
void *HttpConn_newPrivData(struct HttpConn* con, int key, int size, void (*free_fn)(void *))
{
	void *data;

	//NOTE we could check if the key already exists, but that would just slow us down,
	// this would become O(N) where N is number of priv data.   Now we are O(1)

	con->priv_data_vec = realloc(con->priv_data_vec,
		(con->priv_data_count+2) * sizeof(struct priv_data*));
	con->priv_data_vec[con->priv_data_count] = calloc(1, sizeof(struct priv_data));
	data = con->priv_data_vec[con->priv_data_count]->data = calloc(1, size);
	con->priv_data_vec[con->priv_data_count]->key = key;
	con->priv_data_vec[con->priv_data_count]->free_fn = free_fn;
	con->priv_data_count++;
	con->priv_data_vec[con->priv_data_count] = NULL; // NULL term
	return data;
}

void *HttpConn_getPrivData(struct HttpConn* con, int key)
{
	int i;

	for (i = 0; i < con->priv_data_count; i++) {
		if (con->priv_data_vec[i] && con->priv_data_vec[i]->key == key) {
			DBG(5, "found data with key %d=0x%08x\n", key, key);
			return con->priv_data_vec[i]->data;
		}
	}
	return NULL;
}
#endif

