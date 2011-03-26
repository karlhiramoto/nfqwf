/*
Copyright (C) <2010-2011> Karl Hiramoto <karl@hiramoto.org>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

#ifndef HTTP_REQ_H
#define HTTP_REQ_H 1

#include <stdbool.h>
#include <sys/time.h>
#include <ubiqx/ubi_dLinkList.h>
#include "Ipv4Tcp.h"
#include "Rules.h"


#define ZERO_EOL 0
#define ONE_EOL 1
#define TWO_EOL 2

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
		http_method_connect,
		http_method_propfind,   /* RFC 4918 WebDav */
		http_method_proppatch,
		http_method_mkcol,
		http_method_copy,
		http_method_move,
		http_method_lock,
		http_method_unlock,
		http_method_report,   /* RFC 3253 version control. SVN over http uses this */
		http_method_version_control,
		http_method_checkout,
		http_method_checkin,
		http_method_uncheckout,
		http_method_mkworkspace,
};

enum msg_state { msg_state_new, ///newly allocated
		msg_state_partial,  /// more HTTP headers
		msg_state_read_content, /// read POST/PUT data or response data
		msg_state_complete,
		msg_state_last };


struct HttpConn;

#define HTTP_REQ_MAX_CATEGORY_IDS 5

/* Struct to model rfc 2616 messages to/from server and client*/
struct http_msg {
	enum msg_state state;
	uint64_t content_length;  /// from 'Content-Length:'
	uint64_t content_received;  /// content data received of the content length.
	char *buf_line; /// temporary buffer when one line of a header is in multiple packets
	unsigned int buf_line_len; /// length of buffer
	bool chunked; ///   Transfer-Encoding: chunked
	unsigned int chunk_len; /// length of current chunk
	unsigned int chunk_recieved; /// length of current chunk received
};

struct HttpReq {
	ubi_dlNode node;	/** ubiqx "internal" data */
	struct HttpConn *con; /// connection this request is a part of
	unsigned id;  // an auto increment ID for us to track.
	int resp_status_code; /// 200, 304, 404  etc. RFC2616  Section 6.1.1
	enum http_method method; /// GET, POST, etc
	char *host;
	char *path;
	char *url; /** combine host and path, without http://  so will be host/path */
	struct timeval start_time; /** time the request started */
	struct http_msg client_req_msg;  /// data coming from client HTTP Request
	struct http_msg server_resp_msg;  /// data coming from server HTTP response

	/// NOTE  consider putting virus, phishing, malware, category, etc
	/// into some kind of attributes list,
	/// and each filter object can set the attributes it wants.
//	enum Action verdict; /// reject, virus, Phishing, malware, etc
	struct Rule *rule_matched; /// rule that was matched
	int category_id[HTTP_REQ_MAX_CATEGORY_IDS];
	char *reject_reason; /* virus name, or other reason to reject */
	char *category_name;
	int file_scan_fd;
	char *file_scan_tmpfile;
	struct ContentFilter *cf; /* content filter object */
	/// Private data that a filter object may request, will allow different filter objects to share data.
	/// Or it allows a filter object to save its state between request states
	struct PrivData *priv_data;
};

typedef ubi_dlList HttpReq_list_t;
struct ContentFilter;

struct HttpReq * HttpReq_new(struct HttpConn*);

void HttpReq_del(struct HttpReq **req);
// void * HttpReq_newPrivateDataPtr(struct HttpReq *req, int key, void (*free_fn)(void *));
// void * HttpReq_getPrivateDataPtr(struct HttpReq *req, int key);
// int HttpReq_freePrivateDataPtr(struct HttpReq *req, int key);

int HttpReq_processHeaderLine(struct HttpReq *req, bool client_req,
		unsigned char **start_line, unsigned int *buf_len);

int HttpReq_consumeResponseContent(struct HttpReq *req, const unsigned char *data,
	unsigned int len);

void HttpReq_setRuleMatched(struct HttpReq *req, struct Rule *r);
void HttpReq_setRejectReason(struct HttpReq *req, const char *reason);
void HttpReq_setCatName(struct HttpReq *req, const char *name);

/** @}  */

#endif

