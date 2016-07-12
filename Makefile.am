ACLOCAL_AMFLAGS=-I m4

SUBDIRS=doc

bin_PROGRAMS=stpm-keygen stpm-sign stpm-exfiltrate stpm-verify
TESTS=stpm-keygen_test stpm-sign_test common_test pk11_test stpm-verify_test
check_PROGRAMS=$(TESTS)

common_test_SOURCES=\
src/common_test.cc \
src/common.cc \
src/tspiwrap.cc \
src/fake_tspi.cc \
src/libgtest.cc
common_test_CXXFLAGS=-I/usr/src/gtest
common_test_LDFLAGS=
common_test_LDADD=-lpthread

pk11_test_SOURCES=\
src/pk11_test.cc \
src/pk11.cc \
src/common.cc \
src/session.cc \
src/tspiwrap.cc \
src/fake_tspi.cc \
src/libgtest.cc
pk11_test_CXXFLAGS=-I/usr/src/gtest
pk11_test_LDFLAGS=
pk11_test_LDADD=-lpthread

stpm_keygen_SOURCES=\
src/keygen.cc \
src/common.cc \
src/tspiwrap.cc \
src/wrap_main.cc
stpm_keygen_test_SOURCES=\
src/keygen.cc \
src/keygen_test.cc \
src/common.cc \
src/tspiwrap.cc \
src/fake_tspi.cc \
src/libgtest.cc
stpm_keygen_test_CXXFLAGS=-I/usr/src/gtest
stpm_keygen_test_LDFLAGS=
stpm_keygen_test_LDADD=-lpthread

stpm_exfiltrate_SOURCES=\
src/wrap_main.cc \
src/common.cc \
src/tspiwrap.cc \
src/exfiltrate.cc

stpm_sign_SOURCES=\
src/wrap_main.cc \
src/common.cc \
src/tspiwrap.cc \
src/sign.cc
stpm_sign_test_SOURCES=\
src/sign.cc \
src/sign_test.cc \
src/common.cc \
src/tspiwrap.cc \
src/fake_tspi.cc \
src/libgtest.cc
stpm_sign_test_CXXFLAGS=-I/usr/src/gtest
stpm_sign_test_LDFLAGS=
stpm_sign_test_LDADD=-lpthread

stpm_verify_SOURCES=\
src/wrap_main.cc \
src/common.cc \
src/tspiwrap.cc \
src/verify.cc
stpm_verify_test_SOURCES=\
src/verify.cc \
src/verify_test.cc \
src/common.cc \
src/tspiwrap.cc \
src/fake_tspi.cc \
src/libgtest.cc
stpm_verify_test_CXXFLAGS=-I/usr/src/gtest
stpm_verify_test_LDFLAGS=
stpm_verify_test_LDADD=-lpthread

lib_LTLIBRARIES=libsimple-tpm-pk11.la
# Workaround for "object `...' created both with libtool and without".
libsimple_tpm_pk11_la_CXXFLAGS = $(AM_CXXFLAGS)
libsimple_tpm_pk11_la_SOURCES=\
src/pk11.cc \
src/session.cc \
src/tspiwrap.cc \
src/common.cc
libsimple_tpm_pk11_la_LDFLAGS=-version-info 0:0:0

if WITH_PRECOMPILED_GTEST
common_test_LDADD+=-lgtest -lgtest_main
pk11_test_LDADD+=-lgtest -lgtest_main
stpm_keygen_test_LDADD+=-lgtest -lgtest_main
stpm_sign_test_LDADD+=-lgtest -lgtest_main
stpm_verify_test_LDADD+=-lgtest -lgtest_main
endif

check-tpm:
	./testscripts/all.sh

mrproper: maintainer-clean
	rm -f aclocal.m4 configure.scan depcomp missing install-sh config.h.in
	rm -fr config.guess config.sub build-stamp autom4te.cache/
	rm -f Makefile.in configure autoscan*.log debian/debhelper.log
	rm -f debian/substvars debian/files
	rm -fr debian/tmp
	rm -fr m4
	rm -f doc/Makefile.in
