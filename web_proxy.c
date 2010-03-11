#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>

#include <linux/netfilter.h>
#include <netlink/netfilter/nfnl.h>
#include <netlink/route/link.h>

#ifdef HAVE_CONFIG_H
#include "nfq-proxy-config.h"
#endif

#include "ProxyConfig.h"
#include "NfqProxy.h"
#include "nfq_proxy_private.h"

/**Current configuration */
static struct ProxyConfig *conf = NULL;
static bool keep_running = true;
static int exit_pipe[2] = { 0, 0};

/** vector of NfqProxy */
struct NfqProxy **nfq_proxy;

static void sig_HUP_Handler(int sig)
{
	int ret;
	struct ProxyConfig *new_conf;
	struct ProxyConfig *old_conf = conf;

	DBG(1," reload config sig=%d", sig);
	new_conf = ProxyConfig_new();
	ret = ProxyConfig_loadConfig(new_conf, "Xml file");

	if (ret) {
		DBG(1,"Error loading new config %d", ret);
		ProxyConfig_put(&new_conf);
	} else {
		conf = new_conf;
		ProxyConfig_put(&old_conf);
	}
}

static void sig_Handler(int sig)
{
	int ret;
	DBG(1," sig=%d\n", sig);
	keep_running = false;
	ret = write(exit_pipe[1], &sig, sizeof(sig));
	if (ret < 0) {
		DBG(1," error writing to exit_pipe[1]=%d\n", exit_pipe[1]);
	} else if (ret > 0) {
		DBG(1," wrote %d bytes to exit_pipe[1]=%d\n",ret, exit_pipe[1]);
	}
}

struct libnl_cache_ctx {
	struct nl_sock *rt_sock;
	struct nl_cache *link_cache;
};

static struct libnl_cache_ctx * init_libnl_cache(void)
{
	struct libnl_cache_ctx *cache_ctx;
	int err;

	cache_ctx = calloc(1, sizeof(struct libnl_cache_ctx));

	if (!(cache_ctx->rt_sock = nl_socket_alloc()))
		ERROR_FATAL("Unable to allocate netlink route socket\n");

	if ((err = nl_connect(cache_ctx->rt_sock, NETLINK_ROUTE)) < 0)
		ERROR_FATAL("Unable to connect netlink socket: %d %s\n",
			err, nl_geterror(err));

	rtnl_link_alloc_cache(cache_ctx->rt_sock, &cache_ctx->link_cache);
	nl_cache_mngt_provide(cache_ctx->link_cache);

	return cache_ctx;
}

void cleanup_libnl_cache(struct libnl_cache_ctx * cache_ctx)
{
	nl_cache_mngt_unprovide(cache_ctx->link_cache);
	nl_cache_free(cache_ctx->link_cache);
	nl_socket_free(cache_ctx->rt_sock);
	free(cache_ctx);
}
int main(int argc, char *argv[])
{
	int ret;
	int low_q = 1;  // FIXME read this from args
	int high_q = 2;
	int num_queues;
	struct libnl_cache_ctx *cache_ctx = NULL;
	int i;

	conf = ProxyConfig_new();

	//TODO parse argv argc and put in conf
	ProxyConfig_setHighQNum(conf, high_q);
	ProxyConfig_setLowQNum(conf, low_q);

	/* setup sig handler to reload config */
	signal(SIGHUP, sig_HUP_Handler);

	signal(SIGTERM, sig_Handler);
	signal(SIGINT, sig_Handler);

	ret = ProxyConfig_loadConfig(conf, "Xml file");

	cache_ctx = init_libnl_cache();

	num_queues = high_q - low_q;
	if ( num_queues < 0) {
		DBG(1," high/low queue out of order\n");
		BUG();
	}
	nfq_proxy = calloc(1, (sizeof(struct NfqProxy *) * ((high_q - low_q) + 1)));
	for(i = 0; i < num_queues; i++) {
		DBG(1," start thread %d\n", i);
 		nfq_proxy[i] = NfqProxy_new(i + low_q, conf);
		NfqProxy_start(nfq_proxy[i]);
	}
	ret = pipe(exit_pipe);
	if (ret) {
		DBG(1," Error opening pipe %d\n", ret);
	}

	while(keep_running) {
		/*SIGTERM or SIGINT will break us out of here */
// 		sleep(666); /* sleeping with the devil */

		/*NOTE if we want stats to be reported every X seconds,
		this is the place to put the code */

		fd_set rfds;
		int max_fd;
		int fd;

		FD_ZERO(&rfds);

		max_fd = fd = nl_socket_get_fd(cache_ctx->rt_sock);
		FD_SET(fd, &rfds);
		FD_SET(exit_pipe[0], &rfds);

		if (exit_pipe[0] > fd)
			max_fd = exit_pipe[0];
		
		/* wait for an incoming message on the netlink socket */
		ret = select(fd+1, &rfds, NULL, NULL, NULL);

		if (ret) {
			if (FD_ISSET(exit_pipe[0], &rfds)) {
				DBG(1," exit pipe %d set\n", exit_pipe[1]);
				break;
			}
			
			if (FD_ISSET(max_fd, &rfds)) {
				DBG(1," rt_sock+1 fd %d set\n", fd);
				nl_recvmsgs_default(cache_ctx->rt_sock);
			}
		}
	}

	DBG(1," Stopping %d threads\n", num_queues);
	/* tell threads to stop */
	for(i = 0; i < num_queues; i++) {
		NfqProxy_stop(nfq_proxy[i]);
	}

	for(i = 0; i < num_queues; i++) {
		DBG(1," Join thread %d\n", i);
		NfqProxy_join(nfq_proxy[i]);
		NfqProxy_put(&nfq_proxy[i]);
	}

	ProxyConfig_put(&conf);

	cleanup_libnl_cache(cache_ctx);
	free(nfq_proxy);
	return 0;
}

