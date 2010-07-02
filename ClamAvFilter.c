#define _GNU_SOURCE 
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/un.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <time.h>


#ifdef HAVE_CONFIG_H
#include "nfq-web-filter-config.h"
#endif

#include <fnmatch.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include "PrivData.h"
#include "Filter.h"
#include "FilterType.h"
#include "HttpReq.h"
#include "nfq_wf_private.h"
#include "HttpConn.h"

/**
* @ingroup FilterObject
* @defgroup ClamAvFilter Clamav  anti-virus filter
* @{
*/



// default socket path, change if needed
#define DEFAULT_AV_SOCK_PATH "/var/run/clamav/clamd.sock"
#define SKIP_SIZE "skip_size"
/* 1MB default skip size */
#define DEFAULT_SKIP_SIZE 1024*1024

struct ClamAvFilter
{
	FILTER_OBJECT_COMMON

	/// If file larger than this size skip it
	unsigned int skip_size;

	/// if set, path to clamd socket. If NULL use default
	char *socket_path; 
};

#define MAX_VIRUS_URL 512
struct virus_cache_item {
	char *url; /// URL of virus
	char *virus_name; /// name of virus
	time_t last_access; /// last access time of virus
};

/// local cache of URLs that contains viruses
static struct virus_cache_item *virus_cache = NULL;
/// number of URLs in the cache
static unsigned int virus_cache_count = 0;
static pthread_rwlock_t cache_lock;

/**
* @name Constructor and Destructor
* @{
*/

static int ClamAvFilter_destructor(struct Filter *fobj)
{
	struct ClamAvFilter *fo = (struct ClamAvFilter *) fobj; /* filter object */

	if (fo->socket_path) {
		free(fo->socket_path);
	}

	return 0;
}
/** @} */

/**
* @brief read XML to create a clamav filter object
*/
static int ClamAvFilter_load_from_xml(struct Filter *fobj, xmlNode *node)
{
	struct ClamAvFilter *fo = (struct ClamAvFilter *) fobj; /* filter object */
	xmlChar *prop = NULL;
	
	DBG(5, "Loading XML config\n");

	prop = xmlGetProp(node, BAD_CAST SKIP_SIZE);
	if (!prop) {
		ERROR(" filter/clamav objects MUST have '%s' XML props \n", SKIP_SIZE);
		return -1;
	}

	fo->skip_size = atoi((char*) prop);
	if ( (fo->skip_size > (128 * 1024 * 1024)) || fo->skip_size < 10 ) {
		ERROR(" filter/clamav '%s' value %d invalid, setting to default %d bytes\n",
			  SKIP_SIZE, fo->skip_size, DEFAULT_SKIP_SIZE);

		fo->skip_size = DEFAULT_SKIP_SIZE;
	}

	xmlFree(prop);

	prop = xmlGetProp(node, BAD_CAST "socket_path");
	if (prop) {
		fo->socket_path = strdup((char*) prop);
		xmlFree(prop);
	}

	DBG(2, "Loaded clamav Filter object ID=%d skip_size='%d'\n",
		Filter_getFilterId(fobj), fo->skip_size);

	return 0;
}

/**
* @brief compare function for use in qsort() and bsearch() functions.
*/
static int virus_cache_compare(const void *item1, const void *item2)
{
	struct virus_cache_item *virus1 = (struct virus_cache_item *) item1;
	struct virus_cache_item *virus2 = (struct virus_cache_item *) item2;
	return strncasecmp(virus1->url, virus2->url, MAX_VIRUS_URL);
}

/**
* @brief Add a virus to the virus cache
*/
static void add_virus_to_cache(struct HttpReq *req, const char *virus_name)
{
	DBG(5, "virus %d '%s' at %s\n", virus_cache_count, virus_name, req->url);
	pthread_rwlock_wrlock(&cache_lock);
	
	virus_cache = realloc(virus_cache, sizeof(struct virus_cache_item) * (virus_cache_count+1));
	if (!virus_cache) {
		ERROR_FATAL("realloc error \n");
	}
	virus_cache[virus_cache_count].url = strdup(req->url);
	virus_cache[virus_cache_count].virus_name = strdup(virus_name);
	virus_cache[virus_cache_count].last_access = time(NULL);
	virus_cache_count++;
	qsort(virus_cache, virus_cache_count, sizeof(struct virus_cache_item),
		  virus_cache_compare);

	pthread_rwlock_unlock(&cache_lock);
}

static int search_virus_cache(struct HttpReq *req)
{
	struct virus_cache_item search_key;
	struct virus_cache_item *result = NULL;
	enum Action verdict = Action_nomatch; // 0

	if (!virus_cache)
		return Action_nomatch;

	search_key.url = req->url;

	pthread_rwlock_rdlock(&cache_lock);
	result = bsearch(&search_key, virus_cache, virus_cache_count,
			sizeof(struct virus_cache_item), virus_cache_compare);
	if (result) {
		verdict = Action_virus;
		DBG(2, "Cached Virus %s at url %s\n", result->virus_name, req->url);
		HttpReq_setRejectReason(req, result->virus_name);
	}
	pthread_rwlock_unlock(&cache_lock);

	return verdict;
}

struct clamd_ctx {
	int clamd_fd;
	int stream_count;
};

static int __send_clamd_cmd(int clamd_fd, const char *cmd,
	unsigned len, unsigned timeout_sec)
{
	fd_set write_set;
	struct timeval timeout;
	int ret;

	timeout.tv_sec = timeout_sec;
	timeout.tv_usec = 0;

	FD_ZERO(&write_set);
	FD_SET(clamd_fd, &write_set);

	DBG(5, "select fd %d\n", clamd_fd);
	ret = select(clamd_fd +1, NULL, &write_set, NULL, &timeout);

	if (FD_ISSET(clamd_fd, &write_set)) {
		
		DBG(5, "Sending command len=%d\n", len);
		if(send(clamd_fd, cmd, len, 0) < 0) {
			ERROR( "Unable to send command to clamd\n");
			return -1;
		}
		return 0;
	}

	return -1;
}


static int clamd_connect(struct ClamAvFilter *fo) {
	struct sockaddr_un server;
	int sockd;
// 	int flags = 0;
	const char *sock_path;

	if (fo->socket_path) {
		// use configured socket 
		sock_path = fo->socket_path;
	} else {
		// use default
		sock_path = DEFAULT_AV_SOCK_PATH;
	}

	memset((char *) &server, 0, sizeof(server));
	
	server.sun_family = AF_UNIX;
	strncpy(server.sun_path, sock_path, sizeof(server.sun_path));
	
	if((sockd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
		ERROR( "Unable to create clamd socket: %m\n");
		return -1;
	}

	//FIXME TODO move this up to make a non-blocking connect
// 	flags = fcntl(sockd, F_GETFL);
// 	flags = fcntl(sockd, F_SETFL, flags | O_NONBLOCK);
// 
// 	if (flags == -1) {
// 		ERROR( "Unable to make socket non-blocking: %m\n");
// 	}
// 

	if(connect(sockd, (struct sockaddr *) &server, sizeof(struct sockaddr_un)) < 0) {
		close(sockd);
		ERROR("clamd connection to socket %s failed: %m\n", sock_path);
		return -1;
	}
	DBG(5, "connected to  %d  socket='%s'\n", sockd, sock_path);
	

	return sockd;
}

static int clamd_get_result(int sockd, struct HttpReq *req) {
	char buff[2048];
	char name[128];
	int ret;

	buff[0] = 0;

	ret = read(sockd, buff, sizeof(buff));
	if (ret == -1) {
		ERROR( "Can't read socket %m\n");
		return -1;
	}
	DBG(1, "ClamAV msg: '%s'\n", buff);
	if (ret < 2) {
		ERROR( "Too little data to be valid ret=%d\n", ret);
		return -1;
	}

	if (strstr(buff, "FOUND")) {
		name[0] = 0;

		#ifdef ENABLE_STREAM_FILTER
		/* Parse: "stream: Pascal-529 FOUND" */
		sscanf(buff, "stream: %128s FOUND", name);
		#else
		/* Parse: "fd[7]: Pascal-529 FOUND" */
		sscanf(buff, "%*[^:]: %128s FOUND", name);
		#endif

		if (name[0]) {
			add_virus_to_cache(req, name);
			HttpReq_setRejectReason(req, name);
		}
		
		return Action_virus;
	}

	if (strstr(buff, " ERROR")) {
		ERROR( "ClamAV communication error: %s \n", buff);
		return -1;
	}

	return Action_nomatch;
}

static int __wait_for_clamd_response(int clamd_fd, struct HttpReq *req,
	unsigned int timeout_sec)
{
	fd_set read_set;
	struct timeval timeout;
	int ret;

	timeout.tv_sec = timeout_sec;
	timeout.tv_usec = 0;

	FD_ZERO(&read_set);
	FD_SET(clamd_fd, &read_set);

	DBG(5, "Waiting for result\n");

	ret = select(clamd_fd +1, &read_set, NULL, NULL, &timeout);

	if (ret == 0) {
		DBG(1, "Select() timeout\n");
	} else if (ret == -1) {
		ERROR(" select()\n");
	}

	if (FD_ISSET(clamd_fd, &read_set)) {
		DBG(1, " able to read \n");
		ret = clamd_get_result(clamd_fd, req);
		if (ret >= 0) {
			// result
			return ret;
		}
	}

	return Action_nomatch;
}

#ifdef ENABLE_STREAM_FILTER

static void clamd_ctx_free(void *ptr)
{
	struct clamd_ctx *ctx = (struct clamd_ctx*) ptr;

	if (ctx->clamd_fd != -1) {
		// 		__send_clamd_cmd(ctx, "zEND\0", sizeof("zEND"), 0);
		close(ctx->clamd_fd);
	}
	free(ctx);
}

static int clamd_send_chunk(int clamd_fd, const void *data, unsigned int data_len,
	bool end_of_stream)
{
	struct iovec iov[3];
	struct msghdr msg;
	int ret;
	unsigned int len = data_len;
	unsigned int zero;

	memset(iov, 0, sizeof(iov));

	len = htonl(data_len);
	iov[0].iov_base = &len;
	iov[0].iov_len = 4;
	iov[1].iov_base = (void*) data;
	iov[1].iov_len = data_len;
	
	memset(&msg, 0, sizeof(msg));

	msg.msg_iov = &iov[0];

	if (end_of_stream) {
		msg.msg_iovlen = 3;
		zero = 0;
		iov[2].iov_base = &zero;
		iov[2].iov_len = 4;
	} else {
		msg.msg_iovlen = 2;
	}

	DBG(5, "Send to fd %d iovlen=%d\n", clamd_fd, msg.msg_iovlen);

	ret = sendmsg(clamd_fd, &msg, 0);
	if ( ret == -1) {
		ERROR( "Unable to send fd to clamd err=%d=%s\n", errno, strerror(errno));
		return -1;
	}
	DBG(5, "Sent %d byte message\n", ret);

	return ret;
}
#else
// file descriptor scan

static int clamd_scan_fd(int clamd_fd, struct HttpReq *req) {
	struct iovec iov[1];
	struct msghdr msg;
	struct cmsghdr *cmsg;
	char dummy[]="";
	unsigned char fdbuf[CMSG_SPACE(sizeof(int))];
	int *fdptr;

	iov[0].iov_base = dummy;
	iov[0].iov_len = 1;
	memset(&msg, 0, sizeof(msg));
	
	/* Insert FD into msg payload */
	msg.msg_control = fdbuf;
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;
	msg.msg_controllen = CMSG_LEN(sizeof(int));

	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS; /* pass rights to clam  for this FD */

	fdptr = (int *)CMSG_DATA(cmsg);
	*fdptr = req->file_scan_fd;

	if (sendmsg(clamd_fd, &msg, 0) != iov[0].iov_len) {
		ERROR( "Unable to send fd to clamd err=%d=%s\n", errno, strerror(errno));
		return -1;
	}

	return __wait_for_clamd_response(clamd_fd, req,	20);
}

#endif

#ifdef ENABLE_STREAM_FILTER
static int ClamAvFilter_initClamdCtx(struct Filter *fobj, struct HttpReq *req)
{
	struct ClamAvFilter *fo = (struct ClamAvFilter *) fobj; /* filter object */
	struct clamd_ctx *ctx;

	if (req->server_resp_msg.content_length > fo->skip_size)
		return Action_nomatch;

	ctx = (struct clamd_ctx *) PrivData_newData(req->priv_data,
		Filter_getObjId(fobj), sizeof(struct clamd_ctx), clamd_ctx_free);

	if (!ctx) {
		ERROR(" getting new private data\n");
		return Action_nomatch;
	}
	ctx->clamd_fd = clamd_connect(fo);
	DBG(5, "new priv data %p  fd=%d\n", ctx, ctx->clamd_fd);

	return Action_nomatch;
}


static int ClamAvFilter_streamFilter(struct Filter *fobj, struct HttpReq *req,
	const unsigned char *data_stream, unsigned int length)
{
// 	fd_set read_set;
	fd_set write_set;
	struct timeval timeout;
	struct clamd_ctx *ctx;
	int ret;
	bool end_of_stream = false;

	ctx = (struct clamd_ctx *) PrivData_getData(req->priv_data, Filter_getObjId(fobj));
	if (!ctx) {
		DBG(5, "No private data for this req, not filtering \n");
		return Action_nomatch;
	}
	DBG(5, "priv data %p length=%d stream_count=%d\n",
		ctx, length, ctx->stream_count);

	if (ctx->stream_count == 0) {
		// initial startup
		ret = __send_clamd_cmd(ctx, "zINSTREAM\0", sizeof("zINSTREAM"), 5);

		if (length == 0)
			return Action_nomatch;
	}
	ctx->stream_count++;


	// make sure clamd not deadlocked so read from socket, 0 timeout to poll
	__wait_for_clamd_response(ctx, req, 0);
	
	timeout.tv_sec = 5;
	timeout.tv_usec = 0;

// 	FD_ZERO(&read_set);
	FD_ZERO(&write_set);
// 	FD_SET(ctx->clamd_fd, &read_set);
	FD_SET(ctx->clamd_fd, &write_set);

	ret = select(ctx->clamd_fd +1, NULL, &write_set, NULL, &timeout);

	if (ret == 0) {
		DBG(1, "Select() timeout\n");
	} else if (ret == -1) {
		ERROR(" select()\n");
	}


// 	if (FD_ISSET(ctx->clamd_fd, &read_set)) {
// 		DBG(1, " able to read \n");
// 		ret = clamd_get_result(ctx->clamd_fd, req);
// 		if (ret >= 0) {
// 			// return result
// 			return ret;
// 		}
// 	}
	
	if (FD_ISSET(ctx->clamd_fd, &write_set)) {
		if (length && req->server_resp_msg.state == msg_state_complete) {
			end_of_stream = true;
		}
		ret = clamd_send_chunk(ctx->clamd_fd, data_stream, length, end_of_stream);
		if (ret < 0) {
			ERROR(" sending data to clamd\n");
		}
	}
	if (req->server_resp_msg.state == msg_state_complete) {
		// wait for result
		DBG(1, "Wait for result\n");
		return __wait_for_clamd_response(ctx, req, 20);
	}
	// make sure clamd not deadlocked so read from socket, 0 timeout to poll
	__wait_for_clamd_response(ctx, req, 0);

	return Action_nomatch;
}
#endif

/**
* @brief check the virus cache when the 1st packet of the response comes back so we can directly reject it.
*/
static int ClamAvFilter_checkCache(struct Filter *fobj, struct HttpReq *req)
{
	return search_virus_cache(req);
}

static int ClamAvFilter_fileFilter(struct Filter *fobj, struct HttpReq *req)
{
	int ret;
	int clamd_fd;
	struct ClamAvFilter *fo = (struct ClamAvFilter *) fobj; /* filter object */
	DBG(5, "req =%p filter=%p\n", req, fobj);
	if ((req->server_resp_msg.content_length > fo->skip_size) ||
		(req->server_resp_msg.chunk_recieved > fo->skip_size) )
		return Action_nomatch;

	clamd_fd = clamd_connect(fo);
	DBG(1, "clamd_fd = %d \n", clamd_fd);
	if (clamd_fd == -1) {
		return -1;
	}
	ret = __send_clamd_cmd(clamd_fd, "zFILDES", sizeof("zFILDES"), 10);

	ret = clamd_scan_fd(clamd_fd, req);
	close(clamd_fd);

	return ret;
}

static struct Object_ops obj_ops = {
	.obj_type           = "filter/clamav",
	.obj_size           = sizeof(struct ClamAvFilter),
};

static struct Filter_ops ClamAvFilter_obj_ops = {
	.ops                = &obj_ops,
	.foo_destructor     = ClamAvFilter_destructor,
	.foo_load_from_xml  = ClamAvFilter_load_from_xml,
#ifdef ENABLE_STREAM_FILTER
	.foo_request_start  = ClamAvFilter_initClamdCtx,
	.foo_stream_filter  = ClamAvFilter_streamFilter,
#else
	.foo_matches_req = ClamAvFilter_checkCache, 
	.foo_file_filter = ClamAvFilter_fileFilter,
#endif
};


/**
* Initialization function to register this filter type.
*/
static void __init ClamAvFilter_init(void)
{
	DBG(5, "init clamav filter\n");
	pthread_rwlock_init(&cache_lock, NULL);
	FilterType_register(&ClamAvFilter_obj_ops);
}


static void __exit ClamAvFilter_exit(void)
{
	int i;
	DBG(5, "exit clamav filter\n");

	pthread_rwlock_wrlock(&cache_lock);

	for (i = 0; i < virus_cache_count; i++) {
		
		if (virus_cache[i].url)
			free(virus_cache[i].url);

		if (virus_cache[i].virus_name)
			free(virus_cache[i].virus_name);
	}
	free(virus_cache);
	virus_cache = NULL;
	pthread_rwlock_unlock(&cache_lock);

	pthread_rwlock_destroy(&cache_lock);
}

/** @} */

