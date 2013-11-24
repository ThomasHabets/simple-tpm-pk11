ACLOCAL_AMFLAGS=-I m4

bin_PROGRAMS=stpm-keygen stpm-sign
TESTS=stpm-keygen_test stpm-sign_test
check_PROGRAMS=$(TESTS)

stpm_keygen_SOURCES=\
src/keygen.cc \
src/common.cc \
src/wrap_main.cc
stpm_keygen_test_SOURCES=\
src/keygen.cc \
src/keygen_test.cc \
src/common.cc \
src/fake_tspi.cc \
src/libgtest.cc
stpm_keygen_test_CXXFLAGS=-I/usr/src/gtest
stpm_keygen_test_LDFLAGS=

stpm_sign_SOURCES=\
src/wrap_main.cc \
src/common.cc \
src/sign.cc
stpm_sign_test_SOURCES=\
src/sign.cc \
src/sign_test.cc \
src/common.cc \
src/fake_tspi.cc \
src/libgtest.cc
stpm_sign_test_CXXFLAGS=-I/usr/src/gtest
stpm_sign_test_LDFLAGS=

lib_LTLIBRARIES=libsimple-tpm-pk11.la
# Workaround for "object `...' created both with libtool and without".
libsimple_tpm_pk11_la_CXXFLAGS = $(AM_CXXFLAGS)
libsimple_tpm_pk11_la_SOURCES=\
src/pk11.cc \
src/session.cc \
src/common.cc
libsimple_tpm_pk11_la_LDFLAGS=-version-info 0:0:0

mrproper: maintainer-clean
	rm -f aclocal.m4 configure.scan depcomp missing install-sh config.h.in
	rm -fr config.guess config.sub build-stamp autom4te.cache/
	rm -f Makefile.in configure autoscan*.log debian/debhelper.log
	rm -f debian/substvars debian/files
	rm -fr debian/tmp
	rm -fr m4
