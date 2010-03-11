#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>


#ifdef HAVE_CONFIG_H
#include "nfq-proxy-config.h"
#endif

#include "ProxyConfig.h"
#include "NfqProxy.h"
#include "nfq_proxy_private.h"

/**Current configuration */
static struct ProxyConfig *conf = NULL;
static bool keep_running = true;
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
	DBG(1," sig=%d\n", sig);
	keep_running = false;
}

int main(int argc, char *argv[])
{
	int ret;
	int low_q = 1;  // FIXME read this from args
	int high_q = 2;
	int num_queues;
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

	while(keep_running) {
		/*SIGTERM or SIGINT will break us out of here */
		sleep(666); /* sleeping with the devil */

		/*NOTE if we want stats to be reported every X seconds,
		this is the place to put the code */
	}

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

	free(nfq_proxy);
	return 0;
}

