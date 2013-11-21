AC_PREREQ(2.61)
AC_INIT([simple-tpm-pk11], [0.01], [thomas@habets.se])
AC_CONFIG_AUX_DIR([m4])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([foreign subdir-objects])
AM_MAINTAINER_MODE
LT_INIT([dlopen])

AC_CONFIG_SRCDIR([src/common.cc])
AC_CONFIG_HEADER(config.h)

AC_CHECK_LIB([tspi], [Tspi_GetAttribUint32])

AC_PROG_CXX
AC_PROG_INSTALL
AC_SUBST([AM_CXXFLAGS])
AC_SUBST([AM_LDFLAGS])

# Library stuff.
AC_ENABLE_SHARED
AC_DISABLE_STATIC
AC_PROG_LIBTOOL(libtool)

CXXFLAGS="$CXXFLAGS -std=gnu++0x -Wall"

AC_CONFIG_FILES([Makefile])
AC_OUTPUT

echo "
  $PACKAGE_NAME version $PACKAGE_VERSION
  Prefix.........: $prefix
  Debug Build....: $debug
  C Compiler.....: $CC $CFLAGS $CPPFLAGS
  C++ Compiler...: $CXX $CXXFLAGS $CPPFLAGS
  Linker.........: $LD $LDFLAGS $LIBS
"
