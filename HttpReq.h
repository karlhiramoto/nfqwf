#ifndef HTTP_REQ_H
#define HTTP_REQ_H 1

#include <stdbool.h>
#include <ubiqx/ubi_dLinkList.h>
#include "Ipv4Tcp.h"

/**
* @ingroup HttpConn
* @defgroup HttpReq Http Request
* @{
*/

enum http_method { http_method_options, /* RFC 2616   sect 9.2 */
		http_method_get,         /* RFC 2616   sect 9.3 */
		http_method_head,
		http_method_post,
		http_method_put,
		http_method_delete,
		http_method_trace,
		http_method_connect };


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
	char *url; /** combine host and path, without http://  so will be host/path */
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


	
	/// Private data that a filter object may request, will allow different filter objects to share data.
	/// For example a categoryFetchObject to share with a categoryMatchObject
	struct HttpReq_priv_data **priv_data;
};

typedef ubi_dlList HttpReq_list_t;
struct ContentFilter;

struct HttpReq * HttpReq_new(struct HttpConn*);
void * HttpReq_newPrivateDataPtr(struct HttpReq *req, int key, void (*free_fn)(void *));
void * HttpReq_getPrivateDataPtr(struct HttpReq *req, int key);
int HttpReq_freePrivateDataPtr(struct HttpReq *req, int key);

/** @}  */

#endif

