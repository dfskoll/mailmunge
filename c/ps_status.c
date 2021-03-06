/* ps_status.c
 *
 * Somewhat portable implementation of "setproctitle"
 *
 * Copyright (c) 2000-2005, PostgreSQL Global Development Group
 * various details abducted from various places
 */

/* This file was derived from a file in the PostgreSQL database system.
   The PostgreSQL copyright notice follows.

PostgreSQL Database Management System
(formerly known as Postgres, then as Postgres95)

Portions Copyright (c) 1996-2005, PostgreSQL Global Development Group

Portions Copyright (c) 1994, The Regents of the University of California

Permission to use, copy, modify, and distribute this software and its
documentation for any purpose, without fee, and without a written agreement
is hereby granted, provided that the above copyright notice and this
paragraph and the following two paragraphs appear in all copies.

IN NO EVENT SHALL THE UNIVERSITY OF CALIFORNIA BE LIABLE TO ANY PARTY FOR
DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES, INCLUDING
LOST PROFITS, ARISING OUT OF THE USE OF THIS SOFTWARE AND ITS
DOCUMENTATION, EVEN IF THE UNIVERSITY OF CALIFORNIA HAS BEEN ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.

THE UNIVERSITY OF CALIFORNIA SPECIFICALLY DISCLAIMS ANY WARRANTIES,
INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS FOR A PARTICULAR PURPOSE.  THE SOFTWARE PROVIDED HEREUNDER IS
ON AN "AS IS" BASIS, AND THE UNIVERSITY OF CALIFORNIA HAS NO OBLIGATIONS TO
PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR MODIFICATIONS.
*/

#include <unistd.h>
#include <stdlib.h>
#ifdef HAVE_SYS_PSTAT_H
#include <sys/pstat.h>			/* for HP-UX */
#endif
#ifdef HAVE_PS_STRINGS
#include <machine/vmparam.h>	/* for old BSD */
#include <sys/exec.h>
#endif
#if defined(__darwin__)
#include <crt_externs.h>
#endif

#include <string.h>
#include <stdio.h>

#include "config.h"

extern char **environ;


/*------
 * Alternative ways of updating ps display:
 *
 * PS_USE_SETPROCTITLE
 *	   use the function setproctitle(const char *, ...)
 *	   (newer BSD systems)
 * PS_USE_PSTAT
 *	   use the pstat(PSTAT_SETCMD, )
 *	   (HPUX)
 * PS_USE_PS_STRINGS
 *	   assign PS_STRINGS->ps_argvstr = "string"
 *	   (some BSD systems)
 * PS_USE_CHANGE_ARGV
 *	   assign argv[0] = "string"
 *	   (some other BSD systems)
 * PS_USE_CLOBBER_ARGV
 *	   write over the argv and environment area
 *	   (most SysV-like systems)
 * PS_USE_NONE
 *	   don't update ps display
 *	   (This is the default, as it is safest.)
 */
#if defined(HAVE_SETPROCTITLE)
#define PS_USE_SETPROCTITLE
#elif defined(HAVE_PSTAT) && defined(PSTAT_SETCMD)
#define PS_USE_PSTAT
#elif defined(HAVE_PS_STRINGS)
#define PS_USE_PS_STRINGS
#elif (defined(BSD) || defined(__bsdi__) || defined(__hurd__)) && !defined(__darwin__)
#define PS_USE_CHANGE_ARGV
#elif defined(__linux__) || defined(_AIX) || defined(__sgi) || (defined(sun) && !defined(BSD)) || defined(ultrix) || defined(__ksr__) || defined(__osf__) || defined(__QNX__) || defined(__svr4__) || defined(__svr5__) || defined(__darwin__)
#define PS_USE_CLOBBER_ARGV
#else
#define PS_USE_NONE
#endif


/* Different systems want the buffer padded differently */
#if defined(_AIX) || defined(__linux__) || defined(__QNX__) || defined(__svr4__)
#define PS_PADDING '\0'
#else
#define PS_PADDING ' '
#endif


#ifndef PS_USE_CLOBBER_ARGV
/* all but one options need a buffer to write their ps line in */
#define PS_BUFFER_SIZE 256
static char ps_buffer[PS_BUFFER_SIZE];
static const size_t ps_buffer_size = PS_BUFFER_SIZE;
#else			/* PS_USE_CLOBBER_ARGV */
static char *ps_buffer;			/* will point to argv area */
static size_t ps_buffer_size;	/* space determined at run time */
#endif   /* PS_USE_CLOBBER_ARGV */

static size_t ps_buffer_fixed_size;		/* size of the constant prefix */
static int	save_argc;
static char **save_argv;

/*
 * Call this early in startup to save the original argc/argv values.
 * If needed, we make a copy of the original argv[] array to preserve it
 * from being clobbered by subsequent ps_display actions.
 *
 * (The original argv[] will not be overwritten by this routine, but may be
 * overwritten during init_ps_display.	Also, the physical location of the
 * environment strings may be moved, so this should be called before any code
 * that might try to hang onto a getenv() result.)
 */
char	  **
save_ps_display_args(int argc, char **argv)
{
	save_argc = argc;
	save_argv = argv;

#if defined(PS_USE_CLOBBER_ARGV)

	/*
	 * If we're going to overwrite the argv area, count the available space.
	 * Also move the environment to make additional room.
	 */
	{
		char	   *end_of_area = NULL;
		char	  **new_environ;
		int			i;

		/*
		 * check for contiguous argv strings
		 */
		for (i = 0; i < argc; i++)
		{
			if (i == 0 || end_of_area + 1 == argv[i])
				end_of_area = argv[i] + strlen(argv[i]);
		}

		if (end_of_area == NULL)	/* probably can't happen? */
		{
			ps_buffer = NULL;
			ps_buffer_size = 0;
			return argv;
		}

		/*
		 * check for contiguous environ strings following argv
		 */
		for (i = 0; environ[i] != NULL; i++)
		{
			if (end_of_area + 1 == environ[i])
				end_of_area = environ[i] + strlen(environ[i]);
		}

		ps_buffer = argv[0];
		ps_buffer_size = end_of_area - argv[0];

		/*
		 * move the environment out of the way
		 */
		new_environ = (char **) malloc((i + 1) * sizeof(char *));
		for (i = 0; environ[i] != NULL; i++)
			new_environ[i] = strdup(environ[i]);
		new_environ[i] = NULL;
		environ = new_environ;
	}
#endif   /* PS_USE_CLOBBER_ARGV */

#if defined(PS_USE_CHANGE_ARGV) || defined(PS_USE_CLOBBER_ARGV)

	/*
	 * If we're going to change the original argv[] then make a copy for
	 * argument parsing purposes.
	 *
	 * (NB: do NOT think to remove the copying of argv[], even though
	 * postmaster.c finishes looking at argv[] long before we ever consider
	 * changing the ps display.  On some platforms, getopt() keeps pointers
	 * into the argv array, and will get horribly confused when it is
	 * re-called to analyze a subprocess' argument string if the argv storage
	 * has been clobbered meanwhile.  Other platforms have other dependencies
	 * on argv[].
	 */
	{
		char	  **new_argv;
		int			i;

		new_argv = (char **) malloc((argc + 1) * sizeof(char *));
		for (i = 0; i < argc; i++)
			new_argv[i] = strdup(argv[i]);
		new_argv[argc] = NULL;

#if defined(__darwin__)

		/*
		 * Darwin (and perhaps other NeXT-derived platforms?) has a static
		 * copy of the argv pointer, which we may fix like so:
		 */
		*_NSGetArgv() = new_argv;
#endif

		argv = new_argv;
	}
#endif   /* PS_USE_CHANGE_ARGV or PS_USE_CLOBBER_ARGV */

	return argv;
}

/*
 * Call this once during subprocess startup to set the identification
 * values. At this point, the original argv[] array may be overwritten.
 */
void
init_ps_display(char const *fixed_part)
{
#ifndef PS_USE_NONE

#ifdef PS_USE_CLOBBER_ARGV
	/* If ps_buffer is a pointer, it might still be null */
	if (!ps_buffer)
		return;
#endif

	/*
	 * Overwrite argv[] to point at appropriate space, if needed
	 */

#ifdef PS_USE_CHANGE_ARGV
	save_argv[0] = ps_buffer;
	save_argv[1] = NULL;
#endif   /* PS_USE_CHANGE_ARGV */

#ifdef PS_USE_CLOBBER_ARGV
	{
		int			i;

		/* make extra argv slots point at end_of_area (a NUL) */
		for (i = 1; i < save_argc; i++)
			save_argv[i] = ps_buffer + ps_buffer_size;
	}
#endif   /* PS_USE_CLOBBER_ARGV */

	snprintf(ps_buffer, ps_buffer_size,
		 "%s",
		 fixed_part);
	ps_buffer_fixed_size = strlen(ps_buffer);

#endif   /* not PS_USE_NONE */
}

/*
 * Call this to update the ps status display to a fixed prefix plus an
 * indication of what you're currently doing passed in the argument.
 */
void
set_ps_display(const char *activity)
{
#ifndef PS_USE_NONE

#ifdef PS_USE_CLOBBER_ARGV
    /* If ps_buffer is a pointer, it might still be null */
    if (!ps_buffer)
	return;
#endif

    /* Update ps_buffer to contain both fixed part and activity */
    strncpy(ps_buffer + ps_buffer_fixed_size, activity,
	    ps_buffer_size - ps_buffer_fixed_size);
    ps_buffer[ps_buffer_size-1] = 0;

    /* Transmit new setting to kernel, if necessary */
#ifdef PS_USE_SETPROCTITLE
    setproctitle("%s", ps_buffer);
#endif

#ifdef PS_USE_PSTAT
    {
	union pstun pst;

	pst.pst_command = ps_buffer;
	pstat(PSTAT_SETCMD, pst, strlen(ps_buffer), 0, 0);
    }
#endif   /* PS_USE_PSTAT */

#ifdef PS_USE_PS_STRINGS
    PS_STRINGS->ps_nargvstr = 1;
    PS_STRINGS->ps_argvstr = ps_buffer;
#endif   /* PS_USE_PS_STRINGS */

#ifdef PS_USE_CLOBBER_ARGV
    {
	int			buflen;

	/* pad unused memory */
	buflen = strlen(ps_buffer);
	memset(ps_buffer + buflen, PS_PADDING, ps_buffer_size - buflen);
    }
#endif   /* PS_USE_CLOBBER_ARGV */

#endif   /* not PS_USE_NONE */
}
