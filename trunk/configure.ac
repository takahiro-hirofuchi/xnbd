#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.67])
AC_INIT([xNBD], [0.3.0], [t.hirofuchi@aist.go.jp], [xnbd], [https://bitbucket.org/hirofuchi/xnbd/])
AM_INIT_AUTOMAKE([foreign dist-bzip2 no-dist-gzip])
AM_SILENT_RULES([yes])
AC_CONFIG_SRCDIR([xnbd_proxy.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_USE_SYSTEM_EXTENSIONS
LT_INIT([disable-static])

# Checks for programs.
AC_PROG_CC_C99
AC_PROG_AWK
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET

# Checks for libraries.
GLIB_MINIMUM_VERSION=2.32  # has g_atomic_pointer_add(), deprecate g_thread_init()
PKG_CHECK_MODULES([GLIB], [glib-2.0 >= ${GLIB_MINIMUM_VERSION} gthread-2.0 >= ${GLIB_MINIMUM_VERSION}])
AC_SUBST([GLIB_CFLAGS])
AC_SUBST([GLIB_LIBS])

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h inttypes.h netdb.h netinet/in.h stdlib.h string.h sys/file.h sys/ioctl.h sys/socket.h sys/time.h syslog.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_CHECK_MEMBERS([struct stat.st_rdev])
AC_CHECK_DECLS([sys_siglist])
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T

# Checks for library functions.
AC_FUNC_FORK
AC_HEADER_MAJOR
AC_FUNC_MMAP
AC_FUNC_STRNLEN
AC_CHECK_FUNCS([alarm dup2 ftruncate getpagesize memset munmap realpath socket strerror])

# Compile flags
AC_ARG_ENABLE([debug], AC_HELP_STRING([--enable-debug], [enable debugging [default=no]]), [
	CFLAGS+=" -g -O0"
	CPPFLAGS+="-DXNBD_DEBUG"
])

CFLAGS+=" -Wall -Wextra -Wformat=2 -Wcast-align -Wwrite-strings -Wfloat-equal -Wpointer-arith -Wswitch-enum -fstack-protector -fstack-check"


AC_CONFIG_FILES([Makefile
                 doc/Makefile
                 lib/Makefile])
AC_OUTPUT
