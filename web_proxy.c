/**
@mainpage NF_QUEUE based transparent proxy
@author Karl Hiramoto <karl@hiramoto.org>
@date 2010

@section Intro Introduction

This will be a transparent proxy that will take advantage of
linux iptables NF_QUEUE.


@image html NF_QUEUE_Proxy.png  "Packet flow block diagram"

@section DesignReq Design Requirements

<ol>
<li> Rule creation </li>
<li> Function as a HTTP 1.0  and HTTP 1.1 content filter, with persistent connections.  RFC 2616.</li>
<li> Denied pages are redirected to an error page and logged </li>
<li> Logging of source IP, Host, Domain, URL, Content length </li>
<li> Antivirus filter in userspace. </li>
<li> Usage of linux kernel NF_QUEUE </li>
<li> Use one process with multiple threads. </li>
<li> Load balance multiple connections over multiple queue targets  (See man iptables  --queue-balance) </li>
<li> One thread per queue which will create a netlink socket listening to only one queue ID. </li>
<li> Each thread/queue will handle the possibility of multiple connections </li>
<li> Must be tolerant of TCP/IP check-sum faults, out of order packets and packet fragmentation. See TCP RFC 793 </li>
<li> Rule verdicts. Each web filter rule will have various possible verdicts: </li>
<ol>
	<li> NONE:   The filter did not match. </li>
	<li> ACCEPT: The filter matched and we should accept (as is now in webchase) </li>
	<li> REJECT: (as is now in webchase) </li>
	<li> VIRUS: (as is now in webchase) </li>
	<li> PHISHING:  Phishing type page that is reported by google safe browising, or comtrend </li>
	<li> MALWARE: Malware page that is reported by google safe browising, or comtrend </li>
	<li> ALWAYS TRUST:   This may be used to trust a domain, IP or network, and ACCEPT_MARK all connections, we can then bypass all AV and filtering to get a performance boost on this domain. </li>
	</ol>
<li> HTTP request filters modules, based on a filter module API. See @link FilterObject </li>
	<ol>
	<li> Filters on host.domain See: @link HostFilter</li>
	<li> Filters on IP or Network.  See: @link IPFilter </li>
	<li> Filters on URL categories by comtrend. This filter must be asynchronous. We can send the HTTP request to the server and the comtrend API in parallel.  When the 1st packet of the HTTP response comes back from the server, we can check and wait (with timeout) for the response of the comtrend API. </li>
	<li> String filters that match any part of the URL. NOTE: using these is a performance penalty because it implies that the entire connection can not be accepted, to avoid things like http://google.com/translate/porno-website.com </li>
	<li> (Optional) Filters that can read categories of domains listed in squid gaurd config files. http://www.squidguard.org/ </li>
	<li> (Optional) Filter based on Google Safe browsing API http://code.google.com/apis/safebrowsing/ Must be asynchronous same as comtrend </li>
	</ol>
<li> HTTP Response content filters </li>
<li> Send HTTP request contents to antivirus such as clamav </li>
<li> (Optional)  Ability to detect a NF_MARK set by another iptables module, in the future this could be a hardware AV (such as lionic) doing AV on single packets </li>
<li> If Virus detected the result for the URL will be cashed, using this cached result we REJECT subsequent HTTP requests for the URL. </li>
<li> With HTTP requests that have the verdict REJECT, we modify the HTTP response to redirect to a new LOCATION (RFC 2616 Chapter 14.30) to display an error page, or directly inject the error page into the packet.  (Note: we will have to test what works best) </li>
<li> Use XML and libxml2 read/write config file.   This means we can eliminate libconfuse from the system since only webchase uses it, and has memory leaks. nsbd is already linked with libxml2 so comes at no extra memory cost. </li>

</ol>

*/
#include <pthread.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <syslog.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <linux/netfilter.h>
#include <netlink/netfilter/nfnl.h>
#include <netlink/route/link.h>

#ifdef HAVE_CONFIG_H
#include "nfq-web-filter-config.h"
#endif

#include "ProxyConfig.h"
#include "NfqProxy.h"
#include "nfq_proxy_private.h"


/**
* @defgroup Main main() program.
* @{
*/



/**Current configuration */
static struct ProxyConfig *conf = NULL;
static bool keep_running = true;
static int exit_pipe[2] = { 0, 0};
static char *pid_file = NULL;
static char *config_file = NULL;
static int low_q = 1;
static int high_q = 2;

/** vector of NfqProxy */
struct NfqProxy **nfq_proxy;

int debug_level = 0;


static void sig_HUP_Handler(int sig)
{
	int ret;
	struct ProxyConfig *new_conf;
	int i;

	DBG(1," reload config sig=%d pid=%d thread=%d\n",
		sig, getpid(), (int) pthread_self());

	if (!config_file) {
		WARN("No config file arg specified to reload\n");
		return;
	}	
	new_conf = ProxyConfig_new();
	ret = ProxyConfig_loadConfig(new_conf, config_file);

	if (ret) {
		DBG(1,"Error loading new config '%s' ret=%d\n", config_file, ret);
		ProxyConfig_put(&new_conf);
		return;
	}

	conf = new_conf;

	for(i = 0; nfq_proxy && nfq_proxy[i]; i++) {
		DBG(1," reloading config in thread %d\n", i);
		NfqProxy_updateConfig(nfq_proxy[i], conf);
	}
	DBG(1," Finished SIG HUP reload config\n");
}

static void sig_PIPE_Handler(int sig)
{
	//fixme this is for testing
	ERROR_FATAL("SIG PIPE received \n\n");
}

static void sig_Handler(int sig)
{
	int ret;
	int id = 0;

	id = pthread_self();
	DBG(1," sig=%d pid=%d thread=%d\n",
		sig, getpid(), id);
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

static void cleanup_libnl_cache(struct libnl_cache_ctx * cache_ctx)
{
	nl_cache_mngt_unprovide(cache_ctx->link_cache);
	nl_cache_free(cache_ctx->link_cache);
	nl_close(cache_ctx->rt_sock);
	nl_socket_free(cache_ctx->rt_sock);
	free(cache_ctx);
}


/** Checks if the pidfile lock is free avoiding this way running two
*  instances of the daemon
*
*  @param	pid file name
*  @return	0 or -1 if an error occurred
*/
static int pidfile_chk(const char *pidfile) {
	struct flock fl;
	int lfd, tries, status;
	FILE *pidf;
	const int MAX_PIDFILE_LOCK_TRIES = 10;
	
	/* We set the lock options */
	fl.l_type   = F_WRLCK;
	fl.l_whence = SEEK_SET; // relative to bof
	fl.l_start  = 0L; // from offset zero
	fl.l_len    = 0L; // lock to eof
	
	/* We open pidfile for locking */
	if((pidf = fopen(pidfile, "a+")) != NULL) {
		lfd = fileno(pidf);
		/* We try to get the lock or loop until MAX_PIDFILE_LOCK_TRIES */
		for (tries = 0; tries < MAX_PIDFILE_LOCK_TRIES; tries++) {
			if((status = fcntl(lfd, F_SETLK, &fl)) < 0) {
				if (errno == EACCES || errno == EAGAIN) {
					sleep(1);
					continue;
				} else
					ERROR_FATAL("Lock error status %d on %s: %s\n",status,pidfile,strerror(errno));
			}
			/* successful lock */
			break;
		}
		
		if (status == -1)
			ERROR_FATAL("Cannot lock %s fd %d in %d tries: %s\n", pidfile, lfd,tries, strerror(errno));
		
		/* We truncate the pidfile */
		if (ftruncate( lfd, (off_t) 0) < 0)
			ERROR_FATAL("Error truncating pidfile, %s\n",strerror(errno));
		
		/* We write our pid in it */
		fprintf(pidf, "%d\n", (int) getpid());
		(void) fflush(pidf);
	} else
		ERROR_FATAL("Error while opening pidfile: %s\n",strerror(errno));
	
	return 0;
}

static void print_help(void)
{
	printf(" Usage opts :   [ -d ] [-v | -v N] < -c config.xml >  [ -p /tmp/pid-file.pid ]  \n");
	printf(" -h      this help\n");
	printf(" -v      verbose\n");
	printf(" -v N    verbose level N (0-9)\n");
	printf(" -d      daemonize\n");
	printf(" -c      config file\n");
	printf(" -p      pid file\n");
	printf(" -q N    Low queue number. The value you pass to");
	printf("               iptables --queue-num or --queue-balance q:Q\n");
	printf("               Default value 1 \n");
	printf(" -Q N    High queue number.  The higher number in --queue-balance q:Q\n");
	printf("               Default value is low queue number \n");
	printf("\n");
}

static int parse_opt (int argc, char *argv[])
{	
	int option;
	int ret;
	bool high_q_set = false;
	bool low_q_set = false;
	
	while ((option = getopt(argc, argv, "c:dhp:Q:q:v::")) != -1)
	{
		switch (option)
		{
			case 'c':	/* config file */
				config_file = strdup(optarg);
				DBG(1, "Config file = '%s'\n", config_file);
				break;
			case 'd':	/* daemonize */
				PRINT("Launching daemon\n");
				ret = daemon(0, 0);
				if (ret == -1) {
					perror("daemon ");
					ERROR_FATAL("error becoming daemon\n");
				}
				break;
			case 'h':
				print_help();
				exit(0);
				break;
			case 'v':	// verbose mode
				debug_level = 1;
				if (optarg)
					debug_level = atoi(optarg);

				PRINT("Verbose mode selected. Verbosity level = %d\n", debug_level);
				break;

			case 'p': /* pid file */
				if (!optarg || !optarg[0]) {
					ERROR_FATAL("Missing pid file arg \n");
				}
				pid_file = strdup(optarg);
				break;
			case 'Q': /* Queue number */
				high_q = atoi(optarg);
				if (high_q < 0 || high_q > 65535) {
					ERROR("High queue range must be 0-65535\n");
					return -1;
				}
				high_q_set = true;
				break;
			case 'q': /* Queue number */
				low_q = atoi(optarg);
				if (low_q < 0 || low_q > 65535) {
					ERROR("Low queue range must be 0-65535\n");
					return -1;
				}
				low_q_set = true;
				break;
			default:
				PRINT("Illegal command line option. '%c'\n\n", optopt);
				return -1;
		}
	}

	if (high_q_set && low_q_set && (low_q > high_q)) {
		ERROR("Low queue must be greater than high queue\n");
		return -1;
	}

	if (!low_q_set && high_q_set) {
		ERROR("If only using one queue only set low queue\n");
		return -1;
	} else if (low_q_set && high_q_set) {
		DBG(1, "Using balanced queue range from %d to %d\n", low_q, high_q);
	} else if (low_q_set && !high_q_set) {
		DBG(1, "Using queue %d\n", low_q);
	} else if (!low_q_set && !high_q_set) {
		DBG(1, "Using default queue %d\n", low_q);
	}

	return 0;
	
}

 
int main(int argc, char *argv[])
{
	int ret;
	int num_queues;
	struct libnl_cache_ctx *cache_ctx = NULL;
	int i;

	openlog(PROG_NAME, LOG_PID, LOG_DAEMON);

	PRINT("Version %s Compiled %s %s\n", VERSION_STR, __DATE__, __TIME__);
	if (argc < 2) {
		print_help();
		return -1;
	}
	ret = parse_opt(argc, argv);
	if (ret) {
		print_help();
		ERROR_FATAL("Error parsing options\n");
	}

	if (pid_file) {
		ret = pidfile_chk(pid_file);

		if (ret) {
			ERROR_FATAL("Error creating pidfile\n");
		}
	}
	conf = ProxyConfig_new();


	//TODO parse argv argc and put in conf
	ProxyConfig_setHighQNum(conf, high_q);
	ProxyConfig_setLowQNum(conf, low_q);

	/* setup sig handler to reload config */
	signal(SIGHUP, sig_HUP_Handler);

	signal(SIGTERM, sig_Handler);
	signal(SIGINT, sig_Handler);

	signal(SIGPIPE, sig_PIPE_Handler);

	ret = ProxyConfig_loadConfig(conf, config_file);

	cache_ctx = init_libnl_cache();

	num_queues = high_q - low_q;
	if ( num_queues < 0) {
		DBG(1," high/low queue out of order\n");
		BUG();
	}
	num_queues++;

	nfq_proxy = calloc(1, (sizeof(struct NfqProxy *) * ((num_queues) + 1)));
	for(i = 0; i < num_queues; i++) {
		DBG(1," start thread %d\n", i);
 		nfq_proxy[i] = NfqProxy_new(i + low_q, conf);
		NfqProxy_start(nfq_proxy[i]);
	}
	// done loading config into each thread so put back reference
	ProxyConfig_put(&conf);

	ret = pipe(exit_pipe);
	if (ret) {
		DBG(1," Error opening pipe %d\n", ret);
	}

	while(keep_running) {
		/*NOTE if we want stats to be reported every X seconds,
		this is a good place to put the code */

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

		if (ret > 0) {
			if (FD_ISSET(exit_pipe[0], &rfds)) {
				DBG(1," exit pipe %d set\n", exit_pipe[1]);

			}
			
			if (FD_ISSET(max_fd, &rfds)) {
				DBG(1," rt_sock fd %d set\n", fd);
				nl_recvmsgs_default(cache_ctx->rt_sock);
			}
		} else {
			DBG(1,"select() returned = %d\n", ret);
		}

		DBG(1," keep_running = %d\n", keep_running);
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

	cleanup_libnl_cache(cache_ctx);
	free(nfq_proxy);

	if (config_file) {
		free(config_file);
		config_file = NULL;
	}

	if (pid_file) {
		unlink(pid_file);
		free(pid_file);
	}
	return 0;
}

/** @}  */
