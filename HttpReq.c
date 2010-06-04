#define _GNU_SOURCE /* for memmem and fallocate */

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

#include "ContentFilter.h"
#include "ProxyConfig.h"
#include "HttpReq.h"
#include "HttpConn.h"
#include "Rules.h"
#include "PrivData.h"
#include "nfq_proxy_private.h"

#define MAX(a, b) (a > b ? a : b)
#define MIN(a, b) (a < b ? a : b)

struct HttpReq * HttpReq_new(struct HttpConn *con)
{
	struct HttpReq *req;

	req = calloc(1, sizeof(struct HttpReq));
	req->con = con;
	req->cf = ProxyConfig_getContentFilter(con->config);
	req->priv_data = PrivData_new();
	return req;
}

void HttpReq_del(struct HttpReq **req_in)
{
	struct HttpReq *req = *req_in;

	if (req->host)
		free(req->host);

	if (req->path)
		free(req->path);

	if (req->url)
		free(req->url);

	if (req->client_req_msg.buf_line)
		free(req->client_req_msg.buf_line);

	if (req->server_resp_msg.buf_line)
		free(req->server_resp_msg.buf_line);

	PrivData_del(&req->priv_data);

	if (req->file_scan)
		fclose(req->file_scan);

	free(req);
	*req_in = NULL;
}

static void save_msg_line(struct http_msg *msg, unsigned char *start, unsigned int len)
{
	if (!len) {
		/* malloc(0) makes no sense */
		BUG();
	}
	if (msg->buf_line) {
		/* this would cause a malloc() on top of already allocated line */
		BUG();
	}
	msg->state = msg_state_partial;
	msg->buf_line = malloc(len);
	msg->buf_line_len= len;
	memcpy(msg->buf_line, start, len);
	DBG(7,"Save partial header line for processing later len=%d\n", len);
}


/**
* @brief process a line of the general header or request header, 
* @arg start_line  Pointer to start of line to process
*      NOTE NOT null terminated, may contain multiple or partial lines.
* @arg len   Length of buffer start_line
*/
int HttpReq_processHeaderLine(struct HttpReq *req, bool client_req, unsigned char **start_line, unsigned int *buf_len)
{
	unsigned char *line = *start_line;
	unsigned int len = *buf_len;
	unsigned char *p;
	unsigned char *end;
	int str_len;
	char value_str[16];  // for parsing numbers
	int count;
	struct http_msg *msg;

	if (client_req)
		msg = &req->client_req_msg;
	else
		msg = &req->server_resp_msg;

	if (!req->host && (p = memmem(line, MIN(len, 15), "Host: ", 6))) {
		p = line+6; // skip past "Host: "
		len -= 6;

		// skip white space
		while ((*p == ' ' || *p == '\t') && len > 0) {
			p++;
			len--;
		}

		end = p;
		// while over host name
		while ((*end > ' ' && *end < 127) && len > 0) {
			end++;
			len--;
		}

		if (!len) {
			DBG(1, "Partial request. Possible Host\n");
			save_msg_line(msg, *start_line, *buf_len);
			*start_line = p;
			*buf_len = 0;
			return -1;
		}

		// now should be at the end of the Host:
		str_len = end - p;
		req->host = malloc(str_len+1);
		memcpy(req->host, p, str_len);
		req->host[str_len] = 0; /* NULL term */
		DBG(3, "host = '%s' len=%d\n", req->host, len);
		p = end;  // continue at end of Hostname,  len is already updated.
	} else if (!msg->content_length  // check if not set yet
			&& (p = memmem(line, MIN(len, 16), "Content-Length: ", 16))) {

		str_len = len;  // save as max possible length.
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
			DBG(1, "Partial request. Possible Content-Length\n");
			save_msg_line(msg, *start_line, *buf_len);
			*start_line = p;
			*buf_len = 0;
			return -1;
		}

		// set len to be string length of content-length number
		str_len = end - p;
		if (str_len > 15) {
			ERROR_FATAL("Bug parsing content-length\n");
		}
		memcpy(value_str, p, str_len);
		value_str[str_len] = 0; // NULL term
		msg->content_length = strtoull(value_str, NULL, 0);
		DBG(3, "Content-Length = %llu len=%d\n", msg->content_length, len);
		p = end;  // continue at end of number,  len is already updated.
	} else if (!msg->content_length  // check if not set yet
		&& (p = memmem(line, MIN(len, 19), "Transfer-Encoding: ", 19))) {

		DBG(5, "found 'Transfer-Encoding:'\n");
		str_len = len;  // save as max possible length.
		// with POST/PUT requests there will be content length data part of the POST/PUT
		p += 19;
		len -= 19;
	// FIXME

	
		msg->chunked = true;
	
	} else {
		p = line;  // continue to next line

		/* if this might be worth saving
		 len < 19 because it's the only way it has a partial
		 "Content-Length:", "Host:", "Transfer-Encoding:" that interest us
		 This way we avoid saving large junk, like cookies and Refer tags.
		*/
		if (len < 19 && len)  {

			// check if line contains a EOL
			while (*p != '\n' && *p != '\r' && len) {
				p++;
				len--;
			}
			if (!len && *p != '\n' && *p != '\r') {
				// No end of line  save
				DBG(1, "Partial request. save data\n");
				save_msg_line(msg, *start_line, *buf_len);
				*start_line = p;
				*buf_len = 0;
				return -1;
			}
			/* p should now be at correct stop to count data */
		}

	}

	/* advance to first EOL char */
	while(len && *p != '\n' && *p != '\r') {
		len--;
		p++;
	}

	count = 0;  // count number of \r and \n
	while(len && (*p == '\n' || *p == '\r') && count <=4) {
		len--;
		p++;
		count++;
	}

	*start_line = p; // where to continue at
	*buf_len = len;

	DBG(6, "count=%d len=%d\n", count, len);
	if (count == 4) {
		return TWO_EOL;
	} else if (count == 3) {
		if (*p== '\n')  // strange case with IIS
			return TWO_EOL;
		else // Ends on \r  
			return ONE_EOL;
	} else if (count > 0) {
		return ONE_EOL;
	}

	return ZERO_EOL;
}

static void __check_recvd_content(struct HttpReq *req)
{
	if (req->server_resp_msg.content_length) {
		if (req->server_resp_msg.content_received == req->server_resp_msg.content_length) {
			DBG(1, "All content received\n");
			req->con->cur_response++;
			req->server_resp_msg.state = msg_state_complete;
		} else if (req->server_resp_msg.content_received > req->server_resp_msg.content_length) {
			WARN("content over limit content_received=%llu content_length=%llu\n",
				 req->server_resp_msg.content_received, req->server_resp_msg.content_length);
				 
				 req->con->cur_response++;
				 req->server_resp_msg.state = msg_state_complete;
		}
	}
	DBG(3, "content_received=%lld content_length=%lld\n", req->server_resp_msg.content_received, req->server_resp_msg.content_length);
	
}


int HttpReq_consumeResponseContent(struct HttpReq *req, const unsigned char *data,
	unsigned int len)
{
	bool first_packet =  req->server_resp_msg.content_received ? false : true;
	bool last_packet;
	size_t bytes_written;
	int rc = 0;

	if (!len)
		return 0;

	req->server_resp_msg.content_received += len;
	req->server_resp_msg.state = msg_state_read_content;
	
	__check_recvd_content(req);

	if (req->server_resp_msg.state == msg_state_complete)
		last_packet = true;
	else
		last_packet = false;

	// FIXME check AV skip size
	if (first_packet
		&& (req->server_resp_msg.content_length < 1024*1024)
		&&	ContentFilter_hasFileFilter(req->cf)) {

		req->file_scan = tmpfile();

		if (!req->file_scan) {
			ERROR("creating tmpfile:%d %m\n", errno);
		}
	}
	
	if (req->file_scan) {
		DBG(1, "File scanning enabled write %d bytes\n", len);
		bytes_written = fwrite(data, 1, len, req->file_scan);
		if (bytes_written < len) {
			ERROR(" Writing temp file written=%d\n", bytes_written);
		}
		if (last_packet) {
			fflush(req->file_scan);
			DBG(1, "last packet scanning file\n");
			rc = ContentFilter_fileScan(req->cf, req);
			if (rc) {
				DBG(1, "file scan returned %d\n", rc);
				return rc;
			}
		} else {
			// TODO fix me check if over skip size
		}
		
	}

	return ContentFilter_filterStream(req->cf, req, data, len);
}



void HttpReq_setRejectReason(struct HttpReq *req, const char *reason)
{
	if (req->reject_reason) {
		/* someone is overwriting the reason, free the old*/
		free(req->reject_reason);
	}
	req->reject_reason = strdup(reason);
}
