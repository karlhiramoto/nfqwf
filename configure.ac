AC_INIT([NF_QUEUE based proxy], [0.1], [karl@hiramoto.org], [nfq_web_proxy])
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

AC_CONFIG_HEADERS([nfq-proxy-config.h])


CFLAGS="${CFLAGS} -Os -Wall -Werror -g3 "

AC_LANG([C])
# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([string])

AC_ARG_WITH([libnl],
		AS_HELP_STRING([--with-libnl@<:@=DIR@:>@],
		[use libnl path default is check for it]),
[],
[with_libnl=check])

LDFLAGS_save=$LDFLAGS
AS_IF([test "x$with_libnl" != xno],
	echo "$with_libnl"
	LIBNL="-L$with_libnl/lib -L$with_libnl/lib/.libs"
	LDFLAGS="$LDFLAGS $LIBNL -lnl-genl -lm"
	[AC_CHECK_LIB([nl], [nl_send_iovec],
	[
		AC_SUBST([LIBNL_LDFLAGS], ["-L$with_libnl/lib -L$with_libnl/lib/.libs -lnl-nf -lnl-route -lnl -lnl-genl -lm"])
		AC_SUBST([LIBNL_CFLAGS], ["-I$with_libnl/include"])
	],
	[if test "x$with_libnl" != xcheck; then
		AC_MSG_FAILURE(
		[--with-libnl was given, but test for libnl failed. shit.])
		fi
	], -lnl)])

LDFLAGS=$LDFLAGS_save

AC_CONFIG_FILES([Makefile
  ])


AC_OUTPUT
