include $(top_srcdir)/aminclude.am

ACLOCAL_AMFLAGS = -I m4

AM_CFLAGS = -DDATADIR='"$(pkgdatadir)"' -pthread
AM_LDFLAGS = -pthread

SUBDIRS = .

if !ENABLE_INTERNAL_PLUGINS
# external plugins for now need the debug_level global variable
# and this should make backtraces useful.
AM_LDFLAGS += -rdynamic
endif


filterdir = $(pkgdatadir)/filter
dist_filter_DATA = clamav.la

PLUGIN_LFLAGS = -module -avoid-version -shared $(AM_LDFLAGS) $(XML2_LDFLAGS)
PLUGIN_FLAGS = $(AM_CFLAGS) $(XML2_INCLUDE)

OBJECT_SOURCES = Object.c

PLUGIN_SOURCES = ClamAvFilter.c HostFilter.c IpFilter.c TimeFilter.c UrlFilter.c
FILTER_SOURCES = ContentFilter.c Filter.c \
	 FilterList.c  FilterType.c Rules.c

bin_PROGRAMS = nfqwf


if ENABLE_TESTS
noinst_bin_PROGRAMS = filter_test1
noinst_bindir = $(abs_top_builddir)/tests

filter_test1_SOURCES = tests/filter_test1.c $(PLUGIN_SOURCES) $(FILTER_SOURCES) \
	$(OBJECT_SOURCES) HttpConn.c HttpReq.c  Ipv4Tcp.c WfConfig.c PrivData.c
filter_test1_CFLAGS = $(AM_CFLAGS) $(LIBNL_CFLAGS) $(XML2_INCLUDE)
filter_test1_LDFLAGS = $(AM_LDFLAGS) $(XML2_LDFLAGS) $(LIBNL_LDFLAGS) \
	-lubiqx
endif


nfqwf_SOURCES =  $(FILTER_SOURCES) \
	Ipv4Tcp.c WfConfig.c PrivData.c \
	HttpConn.c HttpReq.c NfQueue.c Object.c web_filter.c


nfqwf_CFLAGS = $(AM_CFLAGS) $(LIBNL_CFLAGS) $(XML2_INCLUDE)
nfqwf_LDFLAGS = $(AM_LDFLAGS) $(LIBNL_LDFLAGS) \
	-lubiqx $(XML2_LDFLAGS)

if ENABLE_INTERNAL_PLUGINS
nfqwf_SOURCES += $(PLUGIN_SOURCES)
else
nfqwf_LDFLAGS += -ldl
endif
# ensure the distribution of the doxygen configuration file
EXTRA_DIST = Doxygen


if !ENABLE_INTERNAL_PLUGINS
#filter plugins
filter_LTLIBRARIES = clamav.la host.la ip.la time.la url.la

clamav_la_SOURCES = ClamAvFilter.c
clamav_la_CFLAGS = $(PLUGIN_FLAGS)
clamav_la_LDFLAGS = $(PLUGIN_LFLAGS)

host_la_SOURCES = HostFilter.c
host_la_CFLAGS = $(PLUGIN_FLAGS)
host_la_LDFLAGS = $(PLUGIN_LFLAGS)

ip_la_SOURCES = IpFilter.c
ip_la_CFLAGS = $(PLUGIN_FLAGS)
ip_la_LDFLAGS = $(PLUGIN_LFLAGS)

time_la_SOURCES = TimeFilter.c
time_la_CFLAGS = $(PLUGIN_FLAGS)
time_la_LDFLAGS = $(PLUGIN_LFLAGS)

url_la_SOURCES = UrlFilter.c
url_la_CFLAGS = $(PLUGIN_FLAGS)
url_la_LDFLAGS = $(PLUGIN_LFLAGS)
endif
