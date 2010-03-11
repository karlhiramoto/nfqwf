include $(top_srcdir)/aminclude.am

ACLOCAL_AMFLAGS = -I m4

PROXY_CFLAGS = -pthread -g3
PROXY_LDLAGS = -pthread

SUBDIRS = .

OBJECT_SOURCES = Object.c
FILTER_SOURCES = Filter.c IpFilter.c DomainFilter.c FilterList.c  FilterType.c ContentFilter.c

bin_PROGRAMS = web_proxy

noinst_bin_PROGRAMS = filter_test1
noinst_bindir = $(abs_top_builddir)/tests

filter_test1_SOURCES = filter_test1.c $(FILTER_SOURCES) $(OBJECT_SOURCES)
filter_test1_CFLAGS = $(AM_CFLAGS)
filter_test1_LDFLAGS = $(WORKQUEUE_LDLAGS)

web_proxy_SOURCES = ContentFilter.c Filter.c HttpConn.c IpFilter.c \
	ProxyConfig.c DomainFilter.c FilterList.c \
	FilterType.c HttpReq.c NfqProxy.c Object.c Rules.c web_proxy.c

web_proxy_CFLAGS = -pthread $(AM_CFLAGS) $(LIBNL_CFLAGS)
web_proxy_LDFLAGS = -pthread $(AM_LDFLAGS) $(LIBNL_LDFLAGS)

# ensure the distribution of the doxygen configuration file
EXTRA_DIST = Doxygen
