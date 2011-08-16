# $Id: acinclude.m4 26529 2009-05-13 15:37:11Z androsyn $ - aclocal.m4 - Autoconf fun...
AC_DEFUN([AC_DEFINE_DIR], [
  test "x$prefix" = xNONE && prefix="$ac_default_prefix"
  test "x$exec_prefix" = xNONE && exec_prefix='${prefix}'
  ac_define_dir=`eval echo [$]$2`
  ac_define_dir=`eval echo [$]ac_define_dir`
  $1="$ac_define_dir"
  AC_SUBST($1)
  ifelse($3, ,
    AC_DEFINE_UNQUOTED($1, "$ac_define_dir"),
    AC_DEFINE_UNQUOTED($1, "$ac_define_dir", $3))
])

AC_DEFUN([AC_SUBST_DIR], [
        ifelse($2,,,$1="[$]$2")
        $1=`(
            test "x$prefix" = xNONE && prefix="$ac_default_prefix"
            test "x$exec_prefix" = xNONE && exec_prefix="${prefix}"
            eval echo \""[$]$1"\"
        )`
        AC_SUBST($1)
])

dnl Check for libsqlite3, based on version found at libdbi-drivers.sf.net (GPLv2-licensed)

AC_DEFUN([AC_FIND_FILE], [
  $3=no
  for i in $2; do
      for j in $1; do
          if test -r "$i/$j"; then
              $3=$i
              break 2
          fi
      done
  done ])

AC_DEFUN([AC_CHECK_SQLITE3], [
  have_sqlite3="no"
  ac_sqlite3="no"
  ac_sqlite3_incdir="no"
  ac_sqlite3_libdir="no"

  # exported variables
  SQLITE3_LIBS=""
  SQLITE3_CFLAGS=""

  AC_ARG_WITH(sqlite3,		AC_HELP_STRING([--with-sqlite3[=dir]],	[Compile with libsqlite3 at given dir]),
      [ ac_sqlite3="$withval" 
        if test "x$withval" != "xno" -a "x$withval" != "xyes"; then
            ac_sqlite3="yes"
            ac_sqlite3_incdir="$withval"/include
            ac_sqlite3_libdir="$withval"/lib
        fi ],
      [ ac_sqlite3="auto" ] )
  AC_ARG_WITH(sqlite3-incdir,	AC_HELP_STRING([--with-sqlite3-incdir],	[Specifies where the SQLite3 include files are.]),
      [  ac_sqlite3_incdir="$withval" ] )
  AC_ARG_WITH(sqlite3-libdir,	AC_HELP_STRING([--with-sqlite3-libdir],	[Specifies where the SQLite3 libraries are.]),
      [  ac_sqlite3_libdir="$withval" ] )

  AC_MSG_CHECKING([for SQLite3])
  
  # Try to automagically find SQLite, either with pkg-config, or without.
  if test "x$ac_sqlite3" = "xauto"; then
      if test "x$PKG_CONFIG" != "xno"; then
          SQLITE3_LIBS=`$PKG_CONFIG --libs sqlite3 2>/dev/null`
          SQLITE3_CFLAGS=`$PKG_CONFIG --cflags sqlite3 2>/dev/null`
          if test "x$SQLITE3_LIBS" = "x" -a "x$SQLITE3_CFLAGS" = "x"; then
	      AC_CHECK_LIB([sqlite3], [sqlite3_open], [ac_sqlite3="yes"], [ac_sqlite3="no"])
	  else
              ac_sqlite3="yes"
          fi
      else
          AC_CHECK_LIB([sqlite3], [sqlite3_open], [ac_sqlite3="yes"], [ac_sqlite3="no"])
      fi
  fi

  if test "x$ac_sqlite3" = "xyes"; then
      if test "$ac_sqlite3_incdir" = "no"; then
          sqlite3_incdirs="/usr/include /usr/local/include /usr/include/sqlite /usr/local/include/sqlite /usr/local/sqlite/include /opt/sqlite/include"
          AC_FIND_FILE(sqlite3.h, $sqlite3_incdirs, ac_sqlite3_incdir)
          if test "$ac_sqlite3_incdir" = "no"; then
              AC_MSG_WARN([Invalid SQLite directory - include files not found.])
              sqlite3_missing=yes
              ac_sqlite3=no
          fi
      fi
      if test "$ac_sqlite3_libdir" = "no"; then
          sqlite3_libdirs="/usr/lib64 /usr/lib /usr/local/lib64 /usr/local/lib /usr/lib/sqlite usr/lib64/sqlite /usr/local/lib/sqlite /usr/local/sqlite/lib /opt/sqlite/lib"
          sqlite3_libs="libsqlite3.so libsqlite3.dylib libsqlite3.a"
          AC_FIND_FILE($sqlite3_libs, $sqlite3_libdirs, ac_sqlite3_libdir)
          if test "$ac_sqlite3_libdir" = "no"; then
              AC_MSG_WARN([Invalid SQLite directory - libraries not found.])
              sqlite3_missing=yes
              ac_sqlite3=no
          fi
      fi
      if test x"$sqlite3_missing" != "xyes"; then
	      have_sqlite3="yes"

	      if test x"$ac_sqlite3_libdir" = xno; then
	          test "x$SQLITE3_LIBS" = "x" && SQLITE3_LIBS="-lsqlite3"
	      else
	          test "x$SQLITE3_LIBS" = "x" && SQLITE3_LIBS="-L$ac_sqlite3_libdir -lsqlite3"
	      fi
	      test x"$ac_sqlite3_incdir" != xno && test "x$SQLITE3_CFLAGS" = "x" && SQLITE3_CFLAGS=-I$ac_sqlite3_incdir

	      AC_SUBST(SQLITE3_LIBS)
	      AC_SUBST(SQLITE3_CFLAGS)
      else
      	     ac_sqlite3=no
      fi
  fi

  AC_MSG_RESULT([$ac_sqlite3])
])


dnl
dnl Useful macros for autoconf to check for ssp-patched gcc
dnl 1.0 - September 2003 - Tiago Sousa <mirage@kaotik.org>
dnl 1.1 - August 2006 - Ted Percival <ted@midg3t.net>
dnl     * Stricter language checking (C or C++)
dnl     * Adds GCC_STACK_PROTECT_LIB to add -lssp to LDFLAGS as necessary
dnl     * Caches all results
dnl     * Uses macros to ensure correct ouput in quiet/silent mode
dnl 1.2 - April 2007 - Ted Percival <ted@midg3t.net>
dnl     * Added GCC_STACK_PROTECTOR macro for simpler (one-line) invocation
dnl     * GCC_STACK_PROTECT_LIB now adds -lssp to LIBS rather than LDFLAGS
dnl
dnl About ssp:
dnl GCC extension for protecting applications from stack-smashing attacks
dnl http://www.research.ibm.com/trl/projects/security/ssp/
dnl
dnl Usage:
dnl Most people will simply call GCC_STACK_PROTECTOR.
dnl If you only use one of C or C++, you can save time by only calling the
dnl macro appropriate for that language. In that case you should also call
dnl GCC_STACK_PROTECT_LIB first.
dnl
dnl GCC_STACK_PROTECTOR
dnl Tries to turn on stack protection for C and C++ by calling the following
dnl three macros with the right languages.
dnl
dnl GCC_STACK_PROTECT_CC
dnl checks -fstack-protector with the C compiler, if it exists then updates
dnl CFLAGS and defines ENABLE_SSP_CC
dnl
dnl GCC_STACK_PROTECT_CXX
dnl checks -fstack-protector with the C++ compiler, if it exists then updates
dnl CXXFLAGS and defines ENABLE_SSP_CXX
dnl
dnl GCC_STACK_PROTECT_LIB
dnl adds -lssp to LIBS if it is available
dnl ssp is usually provided as part of libc, but was previously a separate lib
dnl It does not hurt to add -lssp even if libc provides SSP - in that case
dnl libssp will simply be ignored.
dnl

AC_DEFUN([GCC_STACK_PROTECT_LIB],[
  AC_CACHE_CHECK([whether libssp exists], ssp_cv_lib,
    [ssp_old_libs="$LIBS"
     LIBS="$LIBS -lssp"
     AC_TRY_LINK(,, ssp_cv_lib=yes, ssp_cv_lib=no)
     LIBS="$ssp_old_libs"
    ])
  if test $ssp_cv_lib = yes; then
    LIBS="$LIBS -lssp"
  fi
])

AC_DEFUN([GCC_STACK_PROTECT_CC],[
  AC_LANG_ASSERT(C)
  if test "X$CC" != "X"; then
    AC_CACHE_CHECK([whether ${CC} accepts -fstack-protector],
      ssp_cv_cc,
      [ssp_old_cflags="$CFLAGS"
       CFLAGS="$CFLAGS -fstack-protector"
       AC_TRY_COMPILE(,, ssp_cv_cc=yes, ssp_cv_cc=no)
       CFLAGS="$ssp_old_cflags"
      ])
    if test $ssp_cv_cc = yes; then
      CFLAGS="$CFLAGS -fstack-protector"
      AC_DEFINE([ENABLE_SSP_CC], 1, [Define if SSP C support is enabled.])
    fi
  fi
])

AC_DEFUN([GCC_STACK_PROTECT_CXX],[
  AC_LANG_ASSERT(C++)
  if test "X$CXX" != "X"; then
    AC_CACHE_CHECK([whether ${CXX} accepts -fstack-protector],
      ssp_cv_cxx,
      [ssp_old_cxxflags="$CXXFLAGS"
       CXXFLAGS="$CXXFLAGS -fstack-protector"
       AC_TRY_COMPILE(,, ssp_cv_cxx=yes, ssp_cv_cxx=no)
       CXXFLAGS="$ssp_old_cxxflags"
      ])
    if test $ssp_cv_cxx = yes; then
      CXXFLAGS="$CXXFLAGS -fstack-protector"
      AC_DEFINE([ENABLE_SSP_CXX], 1, [Define if SSP C++ support is enabled.])
    fi
  fi
])

AC_DEFUN([GCC_STACK_PROTECTOR],[
  GCC_STACK_PROTECT_LIB

  AC_LANG_PUSH([C])
  GCC_STACK_PROTECT_CC
  AC_LANG_POP([C])

  AC_LANG_PUSH([C++])
  GCC_STACK_PROTECT_CXX
  AC_LANG_POP([C++])
])

