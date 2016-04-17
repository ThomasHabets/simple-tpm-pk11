AC_PREREQ(2.61)
AC_INIT([simple-tpm-pk11], [0.04], [thomas@habets.se])
AC_CONFIG_AUX_DIR([m4])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([foreign subdir-objects])
AM_MAINTAINER_MODE
LT_INIT([dlopen])

AC_CONFIG_SRCDIR([src/common.cc])
AC_CONFIG_HEADER(config.h)

AC_CHECK_HEADERS([tss/tspi.h], [], [
    [echo "Cannot continue:"]
    [echo " libtspi headers are missing; please install the package providing tss/tspi.h,"]
    [echo " which is libtspi-dev for Debian derivatives."]
    [exit 1]
])
AC_CHECK_LIB([tspi], [Tspi_GetAttribUint32], [], [
    [echo "Cannot continue:"]
    [echo " libtspi is missing the required function Tspi_GetAttribUint32."]
    [exit 1]
])
AC_CHECK_LIB([crypto], [BN_new], [], [
    [echo "Cannot continue:"]
    [echo " libcrypto is missing the required function BN_new."]
    [exit 1]
])
AC_CHECK_HEADERS([opencryptoki/pkcs11.h], [], [
    [echo "Cannot continue:"]
    [echo " opencryptoki headers are missing; please install the package providing"]
    [echo " opencryptoki/pkcs11.h, which is libopencryptoki-dev for Debian derivatives."]
    [exit 1]
])

AC_ARG_WITH(precompiled-gtest,
  [ --with-precompiled-gtest   Use a system-provided precompiled version of gtest],
  [case "${withval}" in
     yes | no ) WITH_PRECOMPILED_GTEST="${withval}" ;;
     *) AC_MSG_ERROR(bad value ${withval} for --with-precompiled-gtest) ;;
   esac],
  [WITH_PRECOMPILED_GTEST="no"]
)
AM_CONDITIONAL([WITH_PRECOMPILED_GTEST], [test "x$WITH_PRECOMPILED_GTEST" = "xyes"])
AS_IF([test "x$WITH_PRECOMPILED_GTEST" = "xyes"], [
    AC_DEFINE([PRECOMPILED_GTEST], [], ["build using precompiled gtest library"])
])

AC_PROG_CXX
AC_PROG_INSTALL
AC_SUBST([AM_CXXFLAGS])
AC_SUBST([AM_LDFLAGS])

# Library stuff.
AC_ENABLE_SHARED
AC_DISABLE_STATIC
LT_INIT(libtool)

CXXFLAGS="-std=gnu++0x -Wall $CXXFLAGS"

AC_CONFIG_FILES([Makefile])
AC_CONFIG_FILES([doc/Makefile])
AC_OUTPUT

echo "
  $PACKAGE_NAME version $PACKAGE_VERSION
  Prefix.........: $prefix
  Debug Build....: $debug
  C Compiler.....: $CC $CFLAGS $CPPFLAGS
  C++ Compiler...: $CXX $CXXFLAGS $CPPFLAGS
  Linker.........: $LD $LDFLAGS $LIBS
"
