## Process this file with autoconf to produce configure.
## In general, the safest way to proceed is to run ./autogen.sh

# make sure we're interpreted by some minimal autoconf
AC_PREREQ([2.59])

AC_INIT([mpse],[0.1])
MPSE_SO_VERSION=0.1

AC_SUBST(MPSE_SO_VERSION)

# The argument here is just something that should be in the current directory
# (for sanity checking)
AC_CONFIG_SRCDIR(README)
AC_CONFIG_MACRO_DIR([m4])
AC_CANONICAL_HOST
AM_INIT_AUTOMAKE([dist-zip])
AC_CONFIG_HEADERS([src/config.h])

AM_MAINTAINER_MODE()
AX_GENERATE_CHANGELOG
# Export the version information (for mpse_version and friends)
TC_VERSION_MAJOR=`expr "$PACKAGE_VERSION" : '\([[0-9]]*\)'`
TC_VERSION_MINOR=`expr "$PACKAGE_VERSION" : '[[0-9]]*\.\([[0-9]]*\)'`
TC_VERSION_PATCH=`expr "$PACKAGE_VERSION" : '[[0-9]]*\.[[0-9]]*\(.*\)$'`
AC_SUBST(MPSE_VERSION_MAJOR)
AC_SUBST(MPSE_VERSION_MINOR)
AC_SUBST(MPSE_VERSION_PATCH)
AC_SUBST(PACKAGE_STRING)

# The user can choose not to compile in the heap-profiler, the
# heap-checker, or the cpu-profiler.  There's also the possibility
# for a 'fully minimal' compile, which leaves out the stacktrace
# code as well.  By default, we include all of these that the
# target system supports.

# Checks for programs.
AC_PROG_CXX
AC_PROG_CC
AC_PROG_CPP
AM_CONDITIONAL(GCC, test "$GCC" = yes)   # let the Makefile know if we're gcc
AM_PROG_CC_C_O      # shrug: autogen.sh suddenly needs this for some reason

AC_PROG_LIBTOOL

AC_C_INLINE
AX_C___ATTRIBUTE__

AC_CHECK_SIZEOF([char])
AC_CHECK_SIZEOF([short])
AC_CHECK_SIZEOF([int])
AC_CHECK_SIZEOF([long int])
AC_CHECK_SIZEOF([long long int])
AC_CHECK_SIZEOF([unsigned int])
AC_CHECK_SIZEOF([unsigned long int])
AC_CHECK_SIZEOF([unsigned long long int])

# Check for int types
AC_CHECK_TYPES([u_int8_t,u_int16_t,u_int32_t,u_int64_t,uint8_t,uint16_t,uint32_t,uint64_t])
AC_CHECK_TYPES([int8_t,int16_t,int32_t,int64_t])

AC_CHECK_TYPES([boolean])

OLD_CFLAGS="$CFLAGS"
CFLAGS="$CFLAGS "
CFLAGS="$OLD_CFLAGS"



AC_LANG_SAVE
AC_LANG_CPLUSPLUS

AC_LANG_RESTORE

# Check if we have an objcopy installed that supports -W
AC_CHECK_TOOL([OBJCOPY], [objcopy], []) 
AS_IF([test -n "$OBJCOPY"], [dnl
  AC_CACHE_CHECK([if $OBJCOPY supports -W], gpt_cv_objcopy_weaken, [dnl
    AC_LINK_IFELSE([AC_LANG_PROGRAM([void foo() {} int main() {return 0;}])], [dnl
      AS_IF(["$OBJCOPY" -W foo conftest$ac_exeext /dev/null],
            [gpt_cv_objcopy_weaken=yes], [gpt_cv_objcopy_weaken=no])],
    [gpt_cv_objcopy_weaken=no])])],
  [gpt_cv_objcopy_weaken=no])
AM_CONDITIONAL(HAVE_OBJCOPY_WEAKEN, test $gpt_cv_objcopy_weaken = yes)


AC_ARG_ENABLE(intel_soft_cpm,
[  --enable-intel-soft-cpm  Enable Intel Soft CPM support],
       enable_intel_soft_cpm="$enableval", enable_intel_soft_cpm="no")

AC_ARG_WITH(intel_soft_cpm_includes,
        [  --with-intel-soft-cpm-includes=DIR      Intel Soft CPM include directory],
        [with_intel_soft_cpm_includes="$withval"],[with_intel_soft_cpm_includes="no"])

AC_ARG_WITH(intel_soft_cpm_libraries,
        [  --with-intel-soft-cpm-libraries=DIR     Intel Soft CPM library directory],
        [with_intel_soft_cpm_libraries="$withval"],[with_intel_soft_cpm_libraries="no"])

if test "x$with_intel_soft_cpm_includes" != "xno"; then 
    enable_intel_soft_cpm="yes"
    CPPFLAGS="${CPPFLAGS} -I${with_intel_soft_cpm_includes}"
fi

if test "x$with_intel_soft_cpm_libraries" != "xno"; then 
    enable_intel_soft_cpm="yes"
    LDFLAGS="${LDFLAGS} -L${with_intel_soft_cpm_libraries}"
    LIBS="${LIBS} -lpm"
fi

AM_CONDITIONAL(HAVE_INTEL_SOFT_CPM, test "x$enable_intel_soft_cpm" = "xyes")
if test "x$enable_intel_soft_cpm" = "xyes"; then
    CPPFLAGS="${CPPFLAGS} -DINTEL_SOFT_CPM"
fi


# Find out what namespace 'normal' STL code lives in
AC_CXX_STL_NAMESPACE

# Figure out where libc has program_invocation_name
AC_PROGRAM_INVOCATION_NAME

# Make the install prefix available, to figure out where to look for pprof
AC_INSTALL_PREFIX

# Write generated configuration file
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
