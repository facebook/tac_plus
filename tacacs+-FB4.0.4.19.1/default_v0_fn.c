/*
 * $Id: default_v0_fn.c,v 1.8 2009-03-17 18:38:12 heas Exp $
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
#include "expire.h"

/* internal state variables */
#define STATE_AUTHEN_START   0	/* no requests issued */
#define STATE_AUTHEN_GETUSER 1	/* username has been requested */
#define STATE_AUTHEN_GETPASS 2	/* password has been requested */

struct private_data {
    char password[MAX_PASSWD_LEN + 1];
    int state;
};

/*
 * Default tacacs login authentication function. Wants a username
 * and a password, and tries to verify them.
 *
 * Choose_authen will ensure that we already have a username before this
 * gets called.
 *
 * We will query for a password and keep it in the method_data.
 *
 * Any strings returned via pointers in authen_data must come from the
 * heap. They will get freed by the caller.
 *
 * Return 0 if data->status is valid, otherwise 1
 */

int
default_v0_fn(struct authen_data *data)
{
    char *name, *passwd;
    struct private_data *p;
    char *prompt;

    p = (struct private_data *) data->method_data;

    /* An abort has been received. Clean up and return */
    if (data->flags & TAC_PLUS_CONTINUE_FLAG_ABORT) {
	if (data->method_data)
	    free(data->method_data);
	data->method_data = NULL;
	return(1);
    }
    /* Initialise method_data if first time through */
    if (!p) {
	p = (struct private_data *) tac_malloc(sizeof(struct private_data));
	memset(p, 0, sizeof(struct private_data));
	data->method_data = p;
	p->state = STATE_AUTHEN_START;
    }

    /* Unless we're enabling, we need a username */
    if (data->service != TAC_PLUS_AUTHEN_SVC_ENABLE &&
	!(char) data->NAS_id->username[0]) {
	switch (p->state) {

	case STATE_AUTHEN_GETUSER:
	    /* we have previously asked for a username but none came back.
	     * This is a gross error */
	    data->status = TAC_PLUS_AUTHEN_STATUS_ERROR;
	    report(LOG_ERR, "%s: No username supplied after GETUSER",
		   session.peer);
	    return(0);

	case STATE_AUTHEN_START:
	    /* No username. Try requesting one */
	    data->status = TAC_PLUS_AUTHEN_STATUS_GETUSER;
	    if (data->service == TAC_PLUS_AUTHEN_SVC_LOGIN) {
		prompt = cfg_get_host_prompt(data->NAS_id->NAS_ip);
		if (prompt == NULL &&
			!STREQ(data->NAS_id->NAS_name, data->NAS_id->NAS_ip)) {
		    prompt = cfg_get_host_prompt(data->NAS_id->NAS_name);
		}
		if (prompt == NULL) {
		    prompt = "\nUser Access Verification\n\nUsername: ";
		}
	    } else {
		prompt = "Username: ";
	    }
	    data->server_msg = tac_strdup(prompt);
	    p->state = STATE_AUTHEN_GETUSER;
	    return(0);

	default:
	    /* something awful has happened. Give up and die */
	    report(LOG_ERR, "%s: default_fn bad state %d",
		   session.peer, p->state);
	    return(1);
	}
    }

    /* we now have a username if we needed one */
    name = data->NAS_id->username;

    /* Do we have a password? */
    passwd = p->password;

    if (!passwd[0]) {

	/* no password yet. Either we need to ask for one and expect to get
	 * called again, or we asked but nothing came back, which is fatal */

	switch (p->state) {
	case STATE_AUTHEN_GETPASS:
	    /* We already asked for a password. This should be the reply */
	    strncpy(passwd, data->client_msg, MAX_PASSWD_LEN);
	    passwd[MAX_PASSWD_LEN + 1] = '\0';
	    break;

	default:
	    data->flags = TAC_PLUS_AUTHEN_FLAG_NOECHO;
	    data->server_msg = tac_strdup("Password: ");
	    data->status = TAC_PLUS_AUTHEN_STATUS_GETPASS;
	    p->state = STATE_AUTHEN_GETPASS;
	    return(0);
	}
    }

    /* We have a username and password. Try validating */
    if (STREQ(name, DEFAULT_USERNAME)) {
	/* Never authenticate this user. It's for authorization only */
	data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;
	if (debug) {
	    report(LOG_DEBUG,
		   "authentication query for '%s' %s from %s rejected",
		   name && name[0] ? name : "unknown",
		   session.port, session.peer);
	}
	return(0);
    }

    /* Assume the worst */
    data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;

    switch (data->service) {
    case TAC_PLUS_AUTHEN_SVC_NASI:
    case TAC_PLUS_AUTHEN_SVC_LOGIN:
    case TAC_PLUS_AUTHEN_SVC_PPP:
	verify(name, passwd, data, TAC_PLUS_RECURSE);
	if (debug)
	    report(LOG_INFO, "login query for '%s' %s from %s %s",
		   name && name[0] ? name : "unknown",
		   data->NAS_id->NAS_port && data->NAS_id->NAS_port[0] ?
		       data->NAS_id->NAS_port : "unknown",
		   session.peer,
		   (data->status == TAC_PLUS_AUTHEN_STATUS_PASS) ?
		   "accepted" : "rejected");
	break;

    default:
	data->status = TAC_PLUS_AUTHEN_STATUS_ERROR;
	report(LOG_ERR, "%s: Bogus service value %d from packet",
	       session.peer, data->service);
	break;
    }

    if (data->method_data)
	free(data->method_data);
    data->method_data = NULL;

    switch (data->status) {
    case TAC_PLUS_AUTHEN_STATUS_ERROR:
    case TAC_PLUS_AUTHEN_STATUS_FAIL:
    case TAC_PLUS_AUTHEN_STATUS_PASS:
	return(0);
    default:
	report(LOG_ERR, "%s: default_v0_fn can't set status %d",
	       session.peer, data->status);
	data->status = TAC_PLUS_AUTHEN_STATUS_ERROR;
	return(1);
    }
}
