ACLOCAL_AMFLAGS = -I m4
AUTOMAKE_OPTIONS = subdir-objects
AM_CPPFLAGS = -I$(top_srcdir)/src

AM_CXXFLAGS =


lib_LTLIBRARIES =

bin_PROGRAMS =

dist_doc_DATA =

if HAVE_INTEL_SOFT_CPM
INTEL_SOFT_CPM_SOURCES = src/sfutil/intel-soft-cpm.c src/sfutil/intel-soft-cpm.h
endif

MPSE_INCLUDES = src/mpse/str_search.h \
    src/mpse/boyer_moore.h \
    src/mpse/mpse.h \
    src/mpse/sf_types.h \
    src/mpse/snort.h \
    src/mpse/snort_debug.h \
    src/mpse/snort_bounds.h \
    src/mpse/sflsq.h \
    src/mpse/sfksearch.h \
    src/mpse/sfrt_trie.h \
    src/mpse/bnfa_search.h \
    src/mpse/acsmx.h \
    src/mpse/hyperscan.h

libmpse_la_CXXFLAGS =

lib_LTLIBRARIES += libmpse.la
libmpse_la_SOURCES = src/mpse/acsmx2.c \
    src/mpse/acsmx2.h \
    src/mpse/acsmx.c \
    src/mpse/acsmx.h \
    src/mpse/bnfa_search.c \
    src/mpse/bnfa_search.h \
    src/mpse/boyer_moore.c \
    src/mpse/boyer_moore.h \
    src/mpse/mpse.c \
    src/mpse/mpse.h \
    src/mpse/sfksearch.c \
    src/mpse/sfksearch.h \
    src/mpse/sfrt_trie.h \
    src/mpse/sflsq.c \
    src/mpse/sflsq.h \
    src/mpse/bitop.h \
    src/mpse/profiler.c \
    src/mpse/profiler.h \
    src/mpse/str_search.c \
    src/mpse/str_search.h \
    src/mpse/sf_types.h \
    src/mpse/snort.h \
    src/mpse/snort_debug.h \
    src/mpse/snort_bounds.h \
    src/mpse/util.c \
    src/mpse/util.h \
    src/mpse/snort.c \
    src/mpse/snort.h \
    src/mpse/hyperscan.c \
    $(INTEL_SOFT_CPM_SOURCES)

libmpse_la_LDFLAGS = -version-info @MPSE_SO_VERSION@ $(AM_LDFLAGS)
libmpse_la_LIBADD = -lhs

bin_PROGRAMS += bm_test
bm_test_SOURCES = src/test/bm_test.c $(MPSE_INCLUDES)
bm_test_LDADD = libmpse.la

bin_PROGRAMS += mpse_test
mpse_test_SOURCES = src/test/mpse_test.c $(MPSE_INCLUDES)
mpse_test_LDADD = libmpse.la


mpseincludedir = $(includedir)/mpse
mpseinclude_HEADERS =  src/mpse/str_search.h \
    src/mpse/boyer_moore.h \
    src/mpse/mpse.h \
    src/mpse/snort.h \
    src/mpse/sf_types.h \
    src/mpse/snort_debug.h \
    src/mpse/snort_bounds.h \
    src/mpse/sflsq.h \
    src/mpse/sfksearch.h \
    src/mpse/sfrt_trie.h \
    src/mpse/bnfa_search.h \
    src/mpse/acsmx.h \
    src/mpse/bitop.h \
    src/mpse/hyperscan.h
