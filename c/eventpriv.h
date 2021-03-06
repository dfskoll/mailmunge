/***********************************************************************
*
* eventpriv.h
*
* Abstraction of select call into "event-handling" to make programming
* easier.  This header includes "private" definitions which users
* of the event-handling code should not care about.
*
* Copyright (C) 2001-2003 Roaring Penguin Software Inc.
* Copyright (C) 2021-2022 by Dianne Skoll
* https://www.mailmunge.org/
*
* This program may be distributed according to the terms of the GNU
* General Public License, version 2.
*
***********************************************************************/

#ifndef INCLUDE_EVENTPRIV_H
#define INCLUDE_EVENTPRIV_H 1
#include "config.h"
#include <sys/time.h>
#include <sys/types.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_POLL_H
#include <poll.h>
#endif

/* Handler structure */
typedef struct EventHandler_t {
    struct EventHandler_t *next; /* Link in list                           */
    int fd;			/* File descriptor for select              */
    unsigned int flags;		/* Select on read or write; enable timeout */
    unsigned int pollflags;     /* Flags returned by poll()                */
    struct timeval tmout;	/* Absolute time for timeout               */
    EventCallbackFunc fn;	/* Callback function                       */
    void *data;			/* Extra data to pass to callback          */
} EventHandler;

/* Selector structure */
typedef struct EventSelector_t {
    EventHandler *handlers;	/* Linked list of EventHandlers            */
    int nestLevel;		/* Event-handling nesting level            */
    int opsPending;		/* True if operations are pending          */
    int destroyPending;		/* If true, a destroy is pending           */
} EventSelector;

/* Private flags */
#define EVENT_FLAG_DELETED 256
#endif
