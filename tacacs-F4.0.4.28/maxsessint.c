/*
 * $Id: maxsess.c,v 1.12 2009-07-16 18:13:19 heas Exp $
 *
 * Copyright (c) 1995-1998 by Cisco systems, Inc.
 *
 * Permission to use, copy, modify, and distribute this software for
 * any purpose and without fee is hereby granted, provided that this
 * copyright and permission notice appear on all copies of the
 * software and supporting documentation, the name of Cisco Systems,
 * Inc. not be used in advertising or publicity pertaining to
 * distribution of the program without specific prior permission, and
 * notice be given in supporting documentation that modification,
 * copying and distribution is by permission of Cisco Systems, Inc.
 *
 * Cisco Systems, Inc. makes no representations about the suitability
 * of this software for any purpose.  THIS SOFTWARE IS PROVIDED ``AS
 * IS'' AND WITHOUT ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING,
 * WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
 * FITNESS FOR A PARTICULAR PURPOSE.
 */

#include "tac_plus.h"

#if HAVE_CTYPE_H
# include <ctype.h>
#endif
#include <poll.h>
#include <signal.h>


/*
 * is_async()
 * Tell if the named NAS port is an async-like device.
 *
 * Finger reports async users, but not ISDN ones (yay).  So we can do
 * a "slow" double check for async, but not ISDN.
 */
static int
is_async(char *portname)
{
    if (isdigit((int) *portname) || !strncmp(portname, "Async", 5) ||
	!strncmp(portname, "tty", 3)) {
	return(1);
    }
    return(0);
}

/*
 * See if this user can have more sessions.
 */
#ifdef MAXSESS
int
maxsess_check_count(char *user, struct author_data *data)
{
    int sess, maxsess;
    struct identity *id;

    /* No max session configured--don't check */
    id = data->id;

#if MAXSESS
    maxsess = cfg_get_intvalue(user, TAC_IS_USER, S_maxsess, TAC_PLUS_RECURSE);
#else
    maxsess = 0;
#endif
    if (!maxsess) {
	if (debug & (DEBUG_MAXSESS_FLAG | DEBUG_AUTHOR_FLAG)) {
	    report(LOG_DEBUG, "%s may run an unlimited number of sessions",
		   user);
	}
	return(0);
    }
    /* Count sessions for this user by looking in our wholog file */
    sess = countuser(id);

    if (debug & (DEBUG_MAXSESS_FLAG | DEBUG_AUTHOR_FLAG)) {
	report(LOG_DEBUG, "user %s is running %d out of a maximum of %d "
	       "sessions", user, sess, maxsess);
    }

#ifdef MAXSESS_FINGER
    if ((sess >= maxsess) && is_async(id->NAS_port)) {
	/*
	 * If we have finger available, double check this count by contacting
	 * the NAS
	 */
	sess = countusers_by_finger(id);
    }
#endif

    /* If it's really too high, don't authorize more services */
    if (sess >= maxsess) {
	char buf[80];

	snprintf(buf, sizeof(buf),
		"Login failed; too many active sessions (%d maximum)", maxsess);

	data->msg = tac_strdup(buf);

	if (debug & (DEBUG_AUTHOR_FLAG | DEBUG_MAXSESS_FLAG)) {
	    report(LOG_DEBUG, data->msg);
	}
	data->status = AUTHOR_STATUS_FAIL;
	data->output_args = NULL;
	data->num_out_args = 0;
	return(1);
    }
    return(0);
}
#endif
