AC_INIT([NF_QUEUE based web filter], [0.1], [karl@hiramoto.org], [nfq_web_filter])
AC_PREREQ(2.61)

AC_CONFIG_MACRO_DIR([m4])

dnl -Wall and -Werror here are NOT CFLAGS, they refer to automake warnings
AM_INIT_AUTOMAKE([-Wall -Werror])
AC_PROG_CC
AC_PROG_LIBTOOL
AM_PROG_CC_C_O


######################################################################
# DOXYGEN SUPPORT
######################################################################


DX_INIT_DOXYGEN([$PACKAGE_NAME],[Doxyfile],doc)

DX_HTML_FEATURE(ON)
# DX_CHM_FEATURE(OFF)
# DX_CHI_FEATURE(OFF)
# DX_MAN_FEATURE(OFF)
# DX_RTF_FEATURE(OFF)
# DX_XML_FEATURE(OFF)
DX_PDF_FEATURE(ON)
# DX_PS_FEATURE(OFF)


######################################################################

AC_CONFIG_HEADERS([nfq-web-filter-config.h])


CFLAGS="${CFLAGS} -Os -Wall -Werror -g3 "

AC_LANG([C])
# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([string])

AC_ARG_WITH([libnl],
		AS_HELP_STRING([--with-libnl@<:@=DIR@:>@],
		[use libnl path default is check for it]),
[],
[])

LDFLAGS_save=$LDFLAGS
LIBNL=""

if test "x$with_libnl" != "x" ; then
	AC_MSG_CHECKING([libnl 2.x])
	echo "$with_libnl"
	LIBNL="-L$with_libnl/lib -L$with_libnl/lib/.libs"
	LDFLAGS="$LDFLAGS $LIBNL -lnl-genl -lm"
	AC_CHECK_LIB([nl], [nl_send_iovec],
	[
		AC_SUBST([LIBNL_LDFLAGS], ["$LIBNL -lnl-nf -lnl-route -lnl -lnl-genl -lm"])
		AC_SUBST([LIBNL_CFLAGS], ["-I$with_libnl/include"])
	],
	[
		AC_MSG_FAILURE([--with-libnl was given, but test for libnl failed.])
	], [])
else
	AC_CHECK_LIB([nl], [nl_send_iovec], [
		AC_SUBST([LIBNL_LDFLAGS], ["-lnl-nf -lnl-route -lnl -lnl-genl -lm"])
	] ,
		[AC_MSG_WARN([ libnl not found try with --with-libnl=LIBNL_BUILD_DIR])])
fi
LDFLAGS=$LDFLAGS_save

AC_ARG_WITH(libxml2-include-dir,
	AS_HELP_STRING([--with-libxml2-include-dir=DIR],
	[location of libxml2 headers])
	,,)

AC_ARG_WITH(libxml2-lib-dir,
	AS_HELP_STRING([--with-libxml2-lib-dir=DIR],
		[location of libxml2 library binary])
	,,)


if test "x$with_libxml2_include_dir" != "x" ; then
	XML2_INCLUDE="-I$with_libxml2_include_dir"
else
	XML2_INCLUDE="-I/usr/include/libxml2/"
fi

if test "x$with_libxml2_lib_dir" != "x" ; then
	XML2_LDFLAGS="-L$with_libxml2_lib_dir -lxml2 -lz"
else
	XML2_LDFLAGS=" -lxml2 -lz"
fi

AC_SUBST(XML2_INCLUDE)
AC_SUBST(XML2_LDFLAGS)


AC_ARG_ENABLE(tests,
	AS_HELP_STRING([--enable-tests],
		[compile test programs]),
	AC_DEFINE([ENABLE_TESTS], [1], [Define if we want extra tests]),
	AC_DEFINE([DISABLE_TESTS], [1], [Disable tests]),
	)


AM_CONDITIONAL([ENABLE_TESTS], [test "$enable_tests" == "yes"])

AC_CONFIG_FILES([Makefile
  ])


AC_OUTPUT
