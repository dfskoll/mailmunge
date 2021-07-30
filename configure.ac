dnl $Id$
dnl Process this file with autoconf to produce a configure script.

AC_INIT(mailmunge, 3.03, , mailmunge, https://www.mailmunge.org/)

dnl UGLY hack... set the --sysconfdir to /etc UNLESS it was explicitly
dnl supplied on the command line.  Autoconf has no other nice way to set
dnl the default to other than ${prefix}/etc

echo $* | fgrep -e '--sysconfdir' > /dev/null 2>&1 || sysconfdir='/etc'

AC_PROG_CC                      dnl Find C compiler
AC_CONFIG_HEADER(c/config.h)

dnl Add some common directories to PATH in case they are not there
PATH=$PATH:/usr/local/bin

AC_PROG_INSTALL

AC_TYPE_LONG_LONG_INT

AC_ARG_ENABLE(embedded-perl, [  --disable-embedded-perl Disable embedded Perl interpreter], ac_cv_embedded_perl=$enableval, ac_cv_embedded_perl=yes)
AC_PATH_PROG(PERL, perl)

dnl Check for socklen_t type
AC_MSG_CHECKING(whether socklen_t is defined)
AC_TRY_COMPILE([
#include <sys/types.h>
#include <sys/socket.h>
], [socklen_t x;], ac_have_socklen_t=yes, ac_have_socklen_t=no)
AC_MSG_RESULT($ac_have_socklen_t)
if test "$ac_have_socklen_t" = "yes" ; then
   AC_DEFINE(HAVE_SOCKLEN_T,[],["Whether we have the variable type socklen_t"])
fi

dnl Check for -fPIE
AC_MSG_CHECKING(whether the -fPIE compiler option is accepted)
OLD_CFLAGS="$CFLAGS"
CFLAGS="-fPIE -Werror -pie"
AC_TRY_COMPILE([
#include <stdio.h>
], [int x;], ac_have_fpie=yes, ac_have_fpie=no)
AC_MSG_RESULT($ac_have_fpie)

if test "$ac_have_fpie" = "yes" ; then
   CFLAGS="$OLD_CFLAGS -fPIE"
   LDFLAGS="$LDFLAGS -pie"
else
   CFLAGS="$OLD_CFLAGS"
fi

for thing in prefix siteprefix vendorprefix installarchlib installprivlib installbin installman1dir installman3dir installscript installsitearch installsitelib; do
    AC_MSG_CHECKING([for Perl installation variable $thing])
    val=`$PERL -V:$thing | sed -e "s/^.*='//" -e "s/';$//"`
    AC_MSG_RESULT($val)
    dnl Stupid m4....
    up=`echo $thing | tr '[[a-z]]' '[[A-Z]]'`
    eval "PERL$up=$val"
done

dnl wait3
dnl We know that wait3 works fine on Solaris 9, but autoconf
dnl sometimes misses it
un=`uname -s -r`
if test "$un" = "SunOS 5.9" ; then
   ac_cv_func_wait3_rusage=yes
fi

AC_FUNC_WAIT3

if test -z "$PERL" ; then
   AC_MSG_ERROR([*** Cannot continue without Perl.  Sorry.])
   exit 1
fi

AC_PATH_PROG(NM, nm)

dnl Allow user to tell us where Sendmail is (or will be)
SENDMAILPROG=no
AC_ARG_WITH(sendmail,
[  --with-sendmail=PATH    specify location of Sendmail binary],
   SENDMAILPROG=$with_sendmail, SENDMAILPROG=no)

MMUSER=""
AC_ARG_WITH(user,
[  --with-user=LOGIN       use LOGIN (default mailmunge) as the mailmunge user],
   MMUSER=$with_user, MMUSER=mailmunge)

AC_SUBST(MMUSER)

MMGROUP=""
AC_ARG_WITH(group,
[  --with-group=GROUP      use GROUP (default mailmunge) as the mailmunge group],
   MMGROUP=$with_group, MMGROUP=mailmunge)

AC_SUBST(MMGROUP)

dnl Allow user to tell us where milter includes are
MILTERINC=
AC_ARG_WITH(milterinc,
[  --with-milterinc=PATH   specify alternative location of milter includes],
   MILTERINC=$with_milterinc, MILTERINC=)

dnl Allow user to tell us where milter libraries are
MILTERLIB=
AC_ARG_WITH(milterlib,
[  --with-milterlib=PATH   specify alternative location of milter libraries],
   MILTERLIB=$with_milterlib, MILTERLIB=)

dnl Allow specification of config dir
AC_ARG_WITH(confsubdir,
[  --with-confsubdir=DIR   specify configuration subdirectory
			  (mailmunge) ],
	CONFSUBDIR="/$with_confsubdir", CONFSUBDIR=/mailmunge)
if test "$CONFSUBDIR" = "/" -o "$CONFSUBDIR" = "//" ; then
   CONFSUBDIR=""
fi

AC_SUBST(CONFSUBDIR)

dnl Allow specification of spool dir
AC_ARG_WITH(spooldir,
[  --with-spooldir=DIR     specify location of spool directory
			  (/var/spool/mailmunge)],
	SPOOLDIR=$with_spooldir, SPOOLDIR=/var/spool/mailmunge)

dnl Allow specification of quarantine dir
AC_ARG_WITH(quarantinedir,
[  --with-quarantinedir=DIR
			  specify location of quarantine directory
			  (/var/spool/mm-quarantine)],
	QDIR=$with_quarantinedir, QDIR=/var/spool/mm-quarantine)

AC_ARG_ENABLE(pthread-flag,
[  --enable-pthread-flag   Supply the -pthread flag to the C compiler], FORCE_PTHREAD_FLAG=-pthread, FORCE_PTHREAD_FLAG="")

AC_ARG_ENABLE(check-perl-modules,
[  --disable-check-perl-modules
			  Disable compile-time checks for Perl modules], ac_cv_perlmodcheck=$enableval, ac_cv_perlmodcheck=yes)

dnl Check for Perl modules
if test "$ac_cv_perlmodcheck" = "no" ; then
   AC_MSG_RESULT([Compile-time checking for Perl modules disabled])
else
    for module in 'IO::Socket' 'IO::Socket::SSL' 'MIME::Tools 5.410 ()' 'MIME::WordDecoder' 'Sys::Syslog'; do
	AC_MSG_CHECKING([for Perl module $module])
	(echo "use lib '$PERLINSTALLSITELIB'; use $module;" ; echo "exit(0);") | $PERL > /dev/null 2>&1
	if test $? != 0 ; then
	    AC_MSG_WARN([*** Error trying to use Perl module $module])
	    AC_MSG_WARN([*** Make sure it is installed])
	    exit 1
	fi
	AC_MSG_RESULT(ok)
    done

fi

dnl Check for ExtUtils::Embed
if test "$ac_cv_embedded_perl" = "no" ; then
    echo "Check for embedded perl disabled by --disable-embedded-perl option"
    HAVE_EXTUTILS_EMBED=no
else
    AC_MSG_CHECKING([for Perl module ExtUtils::Embed])
    (echo "use ExtUtils::Embed;" ; echo "exit(0);") | $PERL > /dev/null 2>&1
    if test $? = 0 ; then
	HAVE_EXTUTILS_EMBED=yes
	AC_MSG_RESULT(ok)
    else
	HAVE_EXTUTILS_EMBED=no
	AC_MSG_RESULT(no)
    fi
fi

AC_CHECK_HEADERS(getopt.h unistd.h stdint.h poll.h stdint.h)

dnl Check if stdint.h defines uint32_t
AC_MSG_CHECKING(whether stdint.h defines uint32_t)
AC_TRY_COMPILE([
#include <stdint.h>
], [uint32_t foo;], ac_uint32_t_defined=yes, ac_uint32_t_defined=no)
AC_MSG_RESULT($ac_uint32_t_defined)

if test "$ac_uint32_t_defined" = "yes" ; then
   AC_DEFINE(HAVE_UINT32_T,[],["whether uint32_t is defined"])
fi

dnl Check if sys/types.h defines uint32_t
AC_MSG_CHECKING(whether sys/types.h defines uint32_t)
AC_TRY_COMPILE([
#include <sys/types.h>
], [uint32_t foo;], ac_uint32_t_defined=yes, ac_uint32_t_defined=no)
AC_MSG_RESULT($ac_uint32_t_defined)

if test "$ac_uint32_t_defined" = "yes" ; then
   AC_DEFINE(HAVE_UINT32_T,[],["whether uint32_t is defined"])
fi

dnl sig_atomic_t
AC_MSG_CHECKING(whether sig_atomic_t is defined)
AC_TRY_COMPILE([
#include <signal.h>
], [sig_atomic_t foo;], ac_have_sig_atomic_t=yes, ac_have_sig_atomic_t=no)
AC_MSG_RESULT($ac_have_sig_atomic_t)
if test "$ac_have_sig_atomic_t" = "yes" ; then
   AC_DEFINE(HAVE_SIG_ATOMIC_T,[],["Whether we have the atomic_t variable type "])
fi

dnl Check if compiler allows "-pthread" option, but only if
dnl we are using GCC

if test "$FORCE_PTHREAD_FLAG" = "-pthread" ; then
   AC_MSG_RESULT(Forcing use of -pthread C compiler flag)
   PTHREAD_FLAG=-pthread
elif test "$GCC" = yes ; then
   AC_MSG_CHECKING([whether ${CC-cc} accepts -pthread])
   echo 'void f(){}' > conftest.c
   if test -z "`${CC-cc} -pthread -c conftest.c 2>&1`"; then
	   ac_cv_prog_cc_pthread=yes
	   PTHREAD_FLAG="-pthread"
   else
	PTHREAD_FLAG=""
	ac_cv_prog_cc_pthread=no
   fi
   AC_MSG_RESULT($ac_cv_prog_cc_pthread)
   rm -f conftest*
else
   PTHREAD_FLAG=""
fi

if test "$HAVE_EXTUTILS_EMBED" = "yes" ; then
   AC_MSG_CHECKING([if we can embed a Perl interpreter in C])
   OLDCFLAGS="$CFLAGS"
   OLDLDFLAGS="$LDFLAGS"
   OLDLIBS="$LIBS"
   LIBS="-lperl $LIBS"
   EMBPERLLDFLAGS="`$PERL -MExtUtils::Embed -e ldopts`"
   EMBPERLCFLAGS="`$PERL -MExtUtils::Embed -e ccopts`"
   LDFLAGS="$EMBPERLLDFLAGS $LDFLAGS"
   CFLAGS="$EMBPERLCFLAGS $CFLAGS"
   AC_TRY_RUN([
#include <EXTERN.h>
#include <perl.h>
#include <stdlib.h>
static PerlInterpreter *my_perl;
int main(int argc, char **argv, char **env) {
    my_perl = perl_alloc();
    if (!my_perl) exit(1);
    exit(0);
}
], EMBED_PERL=yes, EMBED_PERL=no)
   LIBS="$OLDLIBS"
   CFLAGS="$OLDCFLAGS"
   LDFLAGS="$OLDLDFLAGS"
   AC_MSG_RESULT($EMBED_PERL)
else
   EMBED_PERL=no
fi
if test "$EMBED_PERL" = "no" ; then
   EMBPERLCFLAGS=""
   EMBPERLLDFLAGS=""
   EMBPERLLIBS=""
   EMBPERLDEFS=""
   EMBPERLOBJS=""
else
   EMBPERLLIBS="-lperl"
   EMBPERLDEFS="-DEMBED_PERL"
   EMBPERLOBJS="embperl.o xs_init.o"
   # Check for buggy perl interpreter
   AC_MSG_CHECKING([if it is safe to destroy and recreate a Perl interpreter])
   LIBS="-lperl $LIBS"
   LDFLAGS="$EMBPERLLDFLAGS $LDFLAGS"
   CFLAGS="$EMBPERLCFLAGS $CFLAGS $PTHREAD_FLAG"
   AC_TRY_RUN([
#include <EXTERN.h>
#include <perl.h>

static PerlInterpreter *my_perl = NULL;
static char **argv = NULL;

int
make_embedded_interpreter(char **env)
{
    int argc;
    if (!argv) {
        argv = (char **) malloc(6 * sizeof(char *));
    }
    if (my_perl != NULL) {
	perl_destruct(my_perl);
	perl_free(my_perl);
#ifdef PERL_SYS_TERM
    PERL_SYS_TERM();
#endif
	my_perl = NULL;
    }
    argv[0] = "";
    argv[1] = "-e";
    argv[2] = "print(\"\");";
    argv[3] = NULL;
    argc = 3;

#ifdef PERL_SYS_INIT3
    PERL_SYS_INIT3(&argc, &argv, &env);
#endif
    my_perl = perl_alloc();
    if (!my_perl) {
	return -1;
    }
    PERL_SET_CONTEXT(my_perl);
    PL_perl_destruct_level = 1;
    perl_construct(my_perl);
    PL_perl_destruct_level = 1;
    argv[0] = "";
    argv[1] = "-e";
    argv[2] = "print(\"\");";
    argv[3] = NULL;
    argc = 3;
    perl_parse(my_perl, NULL, argc, argv, NULL);
    perl_run(my_perl);
    return 0;
}

int
main(int argc, char **argv, char **env)
{
    make_embedded_interpreter(env);
    make_embedded_interpreter(env);
#ifdef PERL_SYS_TERM
    PERL_SYS_TERM();
#endif
    return 0;
}
], SAFE_EMBED_PERL=yes, SAFE_EMBED_PERL=no)
   LIBS="$OLDLIBS"
   CFLAGS="$OLDCFLAGS"
   LDFLAGS="$OLDLDFLAGS"
   AC_MSG_RESULT($SAFE_EMBED_PERL)
   if test "$SAFE_EMBED_PERL" = "yes" ; then
      EMBPERLDEFS="$EMBPERLDEFS -DSAFE_EMBED_PERL"
   fi
fi

AC_SUBST(EMBPERLCFLAGS)
AC_SUBST(EMBPERLLDFLAGS)
AC_SUBST(EMBPERLLIBS)
AC_SUBST(EMBPERLOBJS)
AC_SUBST(EMBPERLDEFS)

AC_CHECK_LIB(resolv, res_init)
AC_CHECK_LIB(socket, htons)

AC_CHECK_LIB(utils, setproctitle)
AC_CACHE_CHECK([for PS_STRINGS], [ac_cv_var_PS_STRINGS],
[AC_TRY_LINK(
[#include <machine/vmparam.h>
#include <sys/exec.h>
],
[PS_STRINGS->ps_nargvstr = 1;
PS_STRINGS->ps_argvstr = "foo";],
[ac_cv_var_PS_STRINGS=yes],
[ac_cv_var_PS_STRINGS=no])])
if test "$ac_cv_var_PS_STRINGS" = yes ; then
  AC_DEFINE([HAVE_PS_STRINGS], [], [Define to 1 if the PS_STRINGS thing exists.\
])
fi

LIBS_WITHOUT_PTHREAD="$LIBS"
AC_CHECK_LIB(pthread, pthread_once)

dnl Do we have initgroups?
AC_CHECK_FUNCS(initgroups)
AC_CHECK_FUNCS(setrlimit)
AC_CHECK_FUNCS(inet_ntop)
AC_CHECK_FUNCS(setproctitle)

if test "$SPOOLDIR" = "no" -o "$SPOOLDIR" = "" ; then
	SPOOLDIR=/var/spool/mailmunge
fi

if test "$QDIR" = "no" -o "$QDIR" = "" ; then
	QDIR=/var/spool/mailmunge
fi

AC_SUBST(SPOOLDIR)
AC_SUBST(QDIR)

dnl debugging
AC_ARG_ENABLE(debugging, [  --enable-debugging      Add debugging messages to syslog], ac_cv_debugging=$enableval, ac_cv_debugging=no)

if test "$ac_cv_debugging" = yes ; then
    ENABLE_DEBUGGING=-DENABLE_DEBUGGING
else
    ENABLE_DEBUGGING=
fi

dnl find Sendmail
if test "$SENDMAILPROG" = "no" ; then
   AC_PATH_PROG(SENDMAILPROG, sendmail, no, $PATH:/sbin:/usr/sbin:/usr/lib:/usr/libexec)
fi

AC_DEFUN([MM_MILTER_SFIO],[
    AC_MSG_CHECKING([whether libmilter requires -lsfio])
    RESULT=`$NM $LIBMILTER 2>/dev/null | grep sfsprintf; $NM -D $LIBMILTERSO 2>/dev/null | grep sfsprintf`
    if test -z "$RESULT" ; then
	AC_MSG_RESULT(no)
    else
	AC_MSG_RESULT(yes)
	LIBS="$LIBS -lsfio"
    fi
])

AC_DEFUN([MM_SM_LDAP],[
    AC_MSG_CHECKING([whether libsm requires -lldap])
    RESULT=`$NM $LIBSM | grep ldap_`
    if test -z "$RESULT" ; then
	AC_MSG_RESULT(no)
    else
	AC_MSG_RESULT(yes)
	LIBS="$LIBS -lldap -llber"
    fi
])

AC_DEFUN([MM_MILTER_LDAP],[
    AC_MSG_CHECKING([whether libmilter requires -lldap])
    RESULT=`$NM $LIBMILTER 2>/dev/null | grep ldap_; $NM -D $LIBMILTERSO 2>/dev/null | grep ldap_`
    if test -z "$RESULT" ; then
	AC_MSG_RESULT(no)
    else
	AC_MSG_RESULT(yes)
	LIBS="$LIBS -lldap -llber"
    fi
])

AC_DEFUN([MM_MILTER_SM],[
    OLD_LIBS="$LIBS"
    LIBS="$LIBS -lmilter"
    AC_MSG_CHECKING([whether libmilter requires -lsm])
    AC_TRY_LINK(
    [#include "libmilter/mfapi.h"
     #include <string.h>],
    [extern size_t sm_strlcpy(char *, char const *, ssize_t); char foo[10]; sm_strlcpy(foo, "", 0);],
    NEED_LIBSM=no,
    NEED_LIBSM=yes)
    AC_MSG_RESULT($NEED_LIBSM)
    LIBS="$OLD_LIBS"
    if test "$NEED_LIBSM" = yes ; then
       LIBS="$LIBS -lsm"
       MM_SM_LDAP
    else
       MM_MILTER_LDAP
    fi
])

if test "$SENDMAILPROG" = "no" ; then
    AC_MSG_WARN([Oops.. I couldn't find the 'sendmail' program.  Please install])
    AC_MSG_WARN([either Sendmail or Postfix])
    exit 1
fi

dnl GCC warning level
if test "$GCC" = yes; then
    if test "`uname -s`" = Linux; then
	    CFLAGS="$CFLAGS -Wall -Wstrict-prototypes"
    fi
fi

AC_SUBST(ENABLE_DEBUGGING)
AC_SUBST(PTHREAD_FLAG)

dnl Find sendmail include file.  The nasty path is in case you're building
dnl Sendmail at the same level as mailmunge... we want to use that include
dnl file...
SMMILTER=`echo ../sendmail-*/include`
as_test_x='test -e'
as_executable_p='test -e'
# Redefine so AC_PATH_PROG works
as_fn_executable_p() {
test -e "$1"
}

AC_PATH_PROG(MINCLUDE, libmilter/mfapi.h, no, $MILTERINC:$SMMILTER:/usr/include:/usr/local/include:/usr/local/include/sendmail:/opt/local/include)

if test "$MINCLUDE" = "no" ; then
   echo "*** mailmunge requires the Sendmail milter development headers to be installed."
   exit 1
fi

dnl Fix up the include stuff
MINCLUDE=`dirname "$MINCLUDE"`
MINCLUDE=`dirname "$MINCLUDE"`

dnl If MINCLUDE is "/usr/include", do NOT add to include path, because
dnl this messes up compilation with gcc on Solaris.
if test "$MINCLUDE" = "/usr/include" ; then
   MINCLUDE=""
else
   MINCLUDE="-I${MINCLUDE}"
fi

AC_CHECK_LIB(milter, smfi_main, GOT_LIBMILTER=1, GOT_LIBMILTER=0)

if test "$GOT_LIBILTER" = "0" ; then
   echo "*** mailmunge requires the Sendmail milter development library to be installed."
   exit 1
fi

dnl Check if our libmilter is old and needs LIBSM.  Also checks if it
dnl needs libldap
MM_MILTER_SM

AC_SUBST(LIBS_WITHOUT_PTHREAD)
dnl evaluated versions of conf dir
CONFDIR_EVAL=`echo ${sysconfdir}${CONFSUBDIR}`
AC_SUBST(CONFDIR_EVAL)
AC_SUBST(LDFLAGS)
AC_SUBST(PERLPREFIX)
AC_SUBST(PERLSITEPREFIX)
AC_SUBST(PERLVENDORPREFIX)
AC_SUBST(PERLINSTALLARCHLIB)
AC_SUBST(PERLINSTALLPRIVLIB)
AC_SUBST(PERLINSTALLBIN)
AC_SUBST(PERLINSTALLMAN1DIR)
AC_SUBST(PERLINSTALLMAN3DIR)
AC_SUBST(PERLINSTALLSCRIPT)
AC_SUBST(PERLINSTALLSITEARCH)
AC_SUBST(PERLINSTALLSITELIB)
AC_SUBST(PERLINSTALLDATA)
AC_SUBST(PERLINSTALLSITEDATA)
AC_SUBST(PERLINSTALLVENDORDATA)
AC_SUBST(PERLINSTALLCONF)
AC_SUBST(PERLINSTALLSITECONF)
AC_SUBST(PERLINSTALLVENDORCONF)

AC_OUTPUT(Makefile c/Makefile script/mailmunge-util pod/mailmunge.pod pod/mailmunge-multiplexor.pod pod/mm-mx-ctrl.pod perl/lib/Mailmunge.pm perl/lib/Mailmunge/Constants.pm systemd-units/mailmunge.service systemd-units/mailmunge-multiplexor.service sysvinit/mailmunge etc/default/mailmunge.sample)

HERE=`pwd`
echo "*** Switching to perl/ directory and running $PERL Makefile.PL..."
cd perl && $PERL Makefile.PL INSTALLDIRS=${PERLINSTALLDIRS-site}
if test "$?" != 0 ; then
   echo "*** $PERL Makefile.PL failed!"
   exit 0
fi

cd $HERE

chmod a+x script/mailmunge-util

if test "$MMUSER" != "" ; then
   id $MMUSER > /dev/null 2>&1
   if test "$?" != 0 ; then
      echo ""
      echo "Note:  The mailmunge user '$MMUSER' does not seem to"
      echo "exist.  Please create this user before continuing."
   fi
fi

if test "$ENABLE_DEBUGGING" != "" ; then
   echo ""
   echo "*** WARNING: You have configured with --enable-debugging."
   echo "*** This will produce LARGE VOLUMES of syslog messages and"
   echo "*** is NOT RECOMMENDED for a production system."
fi
chmod a+x sysvinit/mailmunge
