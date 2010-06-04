include $(top_srcdir)/aminclude.am

ACLOCAL_AMFLAGS = -I m4

PROXY_CFLAGS = -pthread -g3
PROXY_LDLAGS = -pthread

SUBDIRS = .

OBJECT_SOURCES = Object.c
FILTER_SOURCES = ClamAvFilter.c ContentFilter.c HostFilter.c Filter.c \
	IpFilter.c FilterList.c  FilterType.c Rules.c TimeFilter.c UrlFilter.c

bin_PROGRAMS = nfq_web_filter

if ENABLE_TESTS
noinst_bin_PROGRAMS = filter_test1
noinst_bindir = $(abs_top_builddir)/tests

filter_test1_SOURCES = tests/filter_test1.c $(FILTER_SOURCES) \
	$(OBJECT_SOURCES) HttpConn.c HttpReq.c  Ipv4Tcp.c ProxyConfig.c
filter_test1_CFLAGS = $(AM_CFLAGS) $(LIBNL_CFLAGS) $(XML2_INCLUDE)
filter_test1_LDFLAGS = $(AM_LDFLAGS) $(XML2_LDFLAGS) $(LIBNL_LDFLAGS) \
	-lubiqx 
endif


nfq_web_filter_SOURCES =  $(FILTER_SOURCES) \
	Ipv4Tcp.c ProxyConfig.c PrivData.c \
	HttpConn.c HttpReq.c NfqProxy.c Object.c web_proxy.c

nfq_web_filter_CFLAGS = -pthread $(AM_CFLAGS) $(LIBNL_CFLAGS) $(XML2_INCLUDE)
nfq_web_filter_LDFLAGS = -pthread $(AM_LDFLAGS) $(LIBNL_LDFLAGS) \
-lubiqx $(XML2_LDFLAGS) 

# ensure the distribution of the doxygen configuration file
EXTRA_DIST = Doxygen
