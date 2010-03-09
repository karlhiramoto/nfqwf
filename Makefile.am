include $(top_srcdir)/aminclude.am

ACLOCAL_AMFLAGS = -I m4

PROXY_CFLAGS = -pthread -g3
PROXY_LDLAGS = -pthread

SUBDIRS = .

OBJECT_SOURCES = Object.c
FILTER_SOURCES = Filter.c  FilterList.c  FilterType.c

noinst_bin_PROGRAMS = filter_test1
noinst_bindir = $(abs_top_builddir)/tests

filter_test1_SOURCES = filter_test1.c $(FILTER_SOURCES) $(OBJECT_SOURCES)
filter_test1_CFLAGS = $(AM_CFLAGS) $(WORKQUEUE_CFLAGS)
filter_test1_LDFLAGS = $(WORKQUEUE_LDLAGS)


# ensure the distribution of the doxygen configuration file
EXTRA_DIST = Doxygen
