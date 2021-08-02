/***********************************************************************
*
* embperl.c
*
* Routines for manipulating embedded Perl interpreter
*
* Copyright (C) 2003 by Roaring Penguin Software Inc.
*
*  This program may be distributed under the terms of the GNU
*  General Public License, Version 2.
*
***********************************************************************/

#ifdef EMBED_PERL
#include "config.h"
#include <EXTERN.h>
#include <perl.h>
#include <errno.h>
#include <syslog.h>

#ifdef PERL_SET_CONTEXT
#define PSC(x) PERL_SET_CONTEXT(x)
#else
#define PSC(x) (void) 0
#endif

#define PERLPARSE_NUM_ARGS 6

static PerlInterpreter *my_perl = NULL;
extern void xs_init (pTHX);

void
init_embedded_interpreter(int argc, char **argv, char **env)
{
#ifdef PERL_SYS_INIT3
    PERL_SYS_INIT3(&argc, &argv, &env);
#endif
}

void
term_embedded_interpreter(void)
{
    if (my_perl != NULL) {
	PSC(my_perl);
	PERL_SET_INTERP(my_perl);
	PL_perl_destruct_level = 1;
	perl_destruct(my_perl);
	perl_free(my_perl);
#ifdef PERL_SYS_TERM
	PERL_SYS_TERM();
#endif
	my_perl = NULL;
    }
}

static char **argv = NULL;

int
make_embedded_interpreter(char const *progPath,
			  int wantStatusReports,
			  char **env)
{
    int argc;

    /* Why do we malloc argv instead of making it static?  Because on some
       systems, Perl makes horrendously evil assumptions about the alignment
       of argv... we use malloc to get guaranteed worst-case alignment.
       Yes, the Perl innards are completely horrible. */
    if (!argv) {
	argv = (char **) malloc(PERLPARSE_NUM_ARGS * sizeof(char *));
	if (!argv) {
	    fprintf(stderr, "Out of memory allocating argv[] array for embedded Perl!");
	    syslog(LOG_ERR, "Out of memory allocating argv[] array for embedded Perl!");
	    exit(EXIT_FAILURE);
	}
    }
    memset(argv, 0, PERLPARSE_NUM_ARGS * sizeof(char *));

    if (my_perl != NULL) {
#ifdef SAFE_EMBED_PERL
	PSC(my_perl);
	PERL_SET_INTERP(my_perl);
	PL_perl_destruct_level = 1;
	perl_destruct(my_perl);
	perl_free(my_perl);
	my_perl = NULL;
#else
	syslog(LOG_WARNING, "Cannot destroy and recreate a Perl interpreter safely on this platform.  Filter rules will NOT be reread.");
	return 0;
#endif

    }

    argv[0] = "";
    argv[1] = (char *) progPath;
    if (wantStatusReports) {
        argv[2] = "-embserveru";
    } else {
        argv[2] = "-embserver";
    }
    argv[3] = NULL;
    argc = 3;

    my_perl = perl_alloc();
    if (!my_perl) {
	errno = ENOMEM;
	return -1;
    }
    PSC(my_perl);
    PERL_SET_INTERP(my_perl);
    PL_perl_destruct_level = 1;
    perl_construct(my_perl);
    if (perl_parse(my_perl, xs_init, argc, argv, NULL) & 0xFF) {
        fprintf(stderr, "perl_parse failed - you may have an error in %s; please check with perl -c.  MULTIPLEXOR IS TERMINATING.", progPath);
        syslog(LOG_CRIT, "perl_parse failed - you may have an error in %s; please check with perl -c.  MULTIPLEXOR IS TERMINATING.", progPath);
        exit(1);
    }
    perl_run(my_perl);
    return 0;
}

/* Perl caches $$ so the PID is wrong after we fork.  This
   routine fixes it up */
static void
embperl_fix_pid(void)
{
    GV *tmpgv;
    if ((tmpgv = gv_fetchpv("$",TRUE, SVt_PV))) {
	SvREADONLY_off(GvSV(tmpgv));
	sv_setiv(GvSV(tmpgv), PerlProc_getpid());
	SvREADONLY_on(GvSV(tmpgv));
    }
}

extern void init_ps_display(char const *fixed_part);
extern void set_ps_display(char const *activity);
void
run_embedded_filter(int workerno)
{
    char *args[] = { NULL };

    char buf[64];
    snprintf(buf, sizeof(buf), "mailmunge: Filtering worker %d", workerno);
    init_ps_display(buf);
    set_ps_display("");
    PSC(my_perl);
    PERL_SET_INTERP(my_perl);
    embperl_fix_pid();

    perl_call_argv("_mailmunge_do_main_loop", G_DISCARD | G_NOARGS, args);
}

#endif

