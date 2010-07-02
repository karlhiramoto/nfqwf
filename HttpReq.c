#define _GNU_SOURCE /* for memmem and fallocate */

#include <stdlib.h>
#include <stdbool.h>
#include <pthread.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/syscall.h>

#ifdef HAVE_CONFIG_H
#include "nfq-web-filter-config.h"
#endif


#include "Ipv4Tcp.h"
#include "HttpConn.h"

#include "ContentFilter.h"
#include "WfConfig.h"
#include "HttpReq.h"
#include "HttpConn.h"
#include "Rules.h"
#include "PrivData.h"
#include "nfq_wf_private.h"

#define MAX(a, b) (a > b ? a : b)
#define MIN(a, b) (a < b ? a : b)

static void __cleanup_tmpfile(struct HttpReq *req)
{
	if (req->file_scan_fd) {
		close(req->file_scan_fd);
		req->file_scan_fd = 0;
	}

	if (req->file_scan_tmpfile) {
		unlink(req->file_scan_tmpfile);
		free(req->file_scan_tmpfile);
		req->file_scan_tmpfile = NULL;
	}
}
struct HttpReq * HttpReq_new(struct HttpConn *con)
{
	struct HttpReq *req;

	req = calloc(1, sizeof(struct HttpReq));
	req->con = con;
	req->cf = WfConfig_getContentFilter(con->config);
	req->priv_data = PrivData_new();
	gettimeofday(&req->start_time, NULL);
	return req;
}


void HttpReq_del(struct HttpReq **req_in)
{
	struct HttpReq *req = *req_in;

	DBG(5, "Free req %p url='%s'\n", req, req->url);
	if (req->rule_matched) {
		ContentFilter_logReq(req->cf, req);
		Rule_put(&req->rule_matched);
	} else {
		DBG(1, "Free request that did not match any rule \n");
	}

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

	if (req->reject_reason) {
		free(req->reject_reason);
	}

	if (req->category_name) {
		free(req->category_name);
	}

	__cleanup_tmpfile(req);

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
			while (len && *p != '\n' && *p != '\r') {
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
	while(len && (*p == '\n' || *p == '\r') && count < 4) {
		len--;
		p++;
		count++;
	}

	*start_line = p; // where to continue at
	*buf_len = len;

	DBG(6, "count=%d len=%d\n", count, len);
	if (count == 4) {
		return TWO_EOL; /* http header ends with \r\n\r\n */
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
#if 0
/* uclibc 0.9.30 does not have fallocate() but the kernel does*/
#ifndef HAVE_FALLOCATE
static inline int fallocate(int fd, int mode, off_t offset, off_t len)
{
	return syscall(__NR_fallocate, fd, mode, offset, len);
}
#endif
#endif

static int open_tmpfile(struct HttpReq *req)
{
	int ret;

	/* Create temporal file name.. */
	ret = asprintf(&req->file_scan_tmpfile, "%s/req_tmp_%p_%08X",
		WfConfig_getTmpDir(req->con->config), req,
		req->con->tuple.dst_ip);

	if (ret == -1)
		return -1;

	/* incase it already exists remove*/
	unlink(req->file_scan_tmpfile);
	req->file_scan_fd = open(req->file_scan_tmpfile, O_RDWR|O_CREAT|O_EXCL, S_IRUSR|S_IWUSR|S_IRGRP);
	if (req->file_scan_fd == -1) {
		ERROR("failed to open temporal buffer file\n");
		req->file_scan_fd = 0;
		return -1;
	}

	DBG(4, "Open AV tmp file %s fd=%d\n",req->file_scan_tmpfile, req->file_scan_fd);

#if 0
	// if we know the content length
	if (req->server_resp_msg.content_length) {
		ret = fallocate(req->file_scan_fd, FALLOC_FL_KEEP_SIZE, 0, req->server_resp_msg.content_length);

		if (ret) {
			ERROR("fallocate of %llu bytes failed %d %m\n",
				  req->server_resp_msg.content_length, errno);
			__cleanup_tmpfile(req);
			return -1;
		}
	}
#endif
	return 0;
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

	if (first_packet
		&&  WfConfig_getMaxFiltredFileSize(req->con->config) > req->server_resp_msg.content_length
		&&	ContentFilter_hasFileFilter(req->cf)) {

		rc = open_tmpfile(req);
		if (rc == -1) {
			// error opening file
			return -1;
		}
	}
	
	if (req->file_scan_fd) {
		DBG(1, "File scanning enabled write %d bytes\n", len);
		bytes_written = write(req->file_scan_fd, data, len);
		if (bytes_written < len) {
			ERROR(" Writing temp file written=%d\n", bytes_written);
		}
		if (last_packet) {
			DBG(1, "last packet scanning file\n");
			rc = ContentFilter_fileScan(req->cf, req);
			if (rc) {
				DBG(1, "file scan returned %d\n", rc);
				return rc;
			}
		} else {
			// Note if we don't know the content length  we must check if over limit
			if (req->server_resp_msg.content_received >
				WfConfig_getMaxFiltredFileSize(req->con->config)) {
				__cleanup_tmpfile(req);
			}
		}
		
	}

	return ContentFilter_filterStream(req->cf, req, data, len);
}

void HttpReq_setRuleMatched(struct HttpReq *req, struct Rule *r)
{
	if (req->rule_matched) {
		// Release old reference
		Rule_put(&req->rule_matched);
	}

	// get new reference
	Rule_get(r); 
	req->rule_matched = r;

	DBG(5, "Rule %d matched action=0x%x\n", r->rule_id, r->action);
	// if rejected and reason not set
	if ((r->action &
		(Action_reject |Action_virus | Action_malware | Action_phishing))
		&& !req->reject_reason) {

		// if rule has a comment set it as the reject reason
		if (r->comment[0]) {
			HttpReq_setRejectReason(req, r->comment);
		} else if(req->category_name) {
			// there is a category name, set it as reject reason.
			HttpReq_setRejectReason(req, req->category_name);
		}
	}
}

void HttpReq_setRejectReason(struct HttpReq *req, const char *reason)
{
	if (req->reject_reason) {
		/* someone is overwriting the reason, free the old*/
		free(req->reject_reason);
	}
	req->reject_reason = strdup(reason);
}

void HttpReq_setCatName(struct HttpReq *req, const char *name)
{
	if (req->category_name) {
		/* someone is overwriting the reason, free the old*/
		free(req->category_name);
	}
	req->category_name = strdup(name);
}
