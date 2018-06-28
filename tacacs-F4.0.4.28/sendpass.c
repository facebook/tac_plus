/*
 * $Id: sendpass.c,v 1.6 2006-12-13 01:11:37 heas Exp $
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

static int
do_sendpass_fn();

int
sendpass_fn(struct authen_data *data)
{
    int status;
    char *name = data->NAS_id->username;
    char *port = data->NAS_id->NAS_port;

    if (sendauth_only) {
	/* sendpass is disallowed */
	report(LOG_ERR, "%s: %s %s sendpass request rejected",
	       session.peer, session.port, name ? name : "<unknown>");
	data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;
	return(0);
    }

    if (STREQ(name, DEFAULT_USERNAME)) {
	data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;
	status = 0;
    } else {
	status = do_sendpass_fn(data);
    }

    if (debug)
	report(LOG_INFO, "sendpass query for '%s' %s from %s %s",
	       name && name[0] ? name : "unknown",
	       port && port[0] ? port : "unknown",
	       session.peer,
	       (data->status == TAC_PLUS_AUTHEN_STATUS_PASS) ?
	       "accepted" : "rejected");

    return(status);
}

/*
 * Cleartext password information has been requested.  Look this up in
 * the config file. Set authen_data->status.
 *
 * Any strings pointed to by authen_data must come from the heap. They
 * will get freed by the caller.
 *
 * Return 0 if data->status is valid, otherwise 1
 */
static int
do_sendpass_fn(struct authen_data *data)
{
    char *name;
    char *p;
    int expired;
    char *exp_date;
    char *secret;

    data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;

    /* We must have a username */
    if (!data->NAS_id->username[0]) {
	/* choose_authen should have already asked for a username, so this is
	 * a gross error */
	data->status = TAC_PLUS_AUTHEN_STATUS_ERROR;
	data->server_msg = tac_strdup("No username supplied");
	report(LOG_ERR, "%s: No username for sendpass_fn", session.peer);
	return(0);
    }
    name = data->NAS_id->username;

    exp_date = cfg_get_expires(name, TAC_PLUS_RECURSE);

    /* The user exists. Check the expiration date, if any */
    expired = check_expiration(exp_date);

    switch (expired) {
    case PW_EXPIRED:
	data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;
	data->server_msg = tac_strdup("Password has expired");
	return(0);

    default:
	data->status = TAC_PLUS_AUTHEN_STATUS_ERROR;
	data->server_msg = tac_strdup("Bad return value for password "
				      "expiration check");
	report(LOG_ERR, "%s: Bogus return value %d from check_expiration",
	       session.peer, expired);
	return(0);

    case PW_OK:
    case PW_EXPIRING:

	/* The user exists, and has not expired. Return her secret info */
	switch (data->type) {
	case TAC_PLUS_AUTHEN_TYPE_CHAP:
	    secret = cfg_get_chap_secret(name, TAC_PLUS_RECURSE);
	    if (!secret)
		secret = cfg_get_global_secret(name, TAC_PLUS_RECURSE);
	    break;

#ifdef MSCHAP
	case TAC_PLUS_AUTHEN_TYPE_MSCHAP:
	    secret = cfg_get_mschap_secret(name, TAC_PLUS_RECURSE);
	    if (!secret)
		secret = cfg_get_global_secret(name, TAC_PLUS_RECURSE);
	    break;
#endif /* MSCHAP */

	case TAC_PLUS_AUTHEN_TYPE_ARAP:
	    secret = cfg_get_arap_secret(name, TAC_PLUS_RECURSE);
	    if (!secret)
		secret = cfg_get_global_secret(name, TAC_PLUS_RECURSE);
	    break;

	case TAC_PLUS_AUTHEN_TYPE_PAP:
	    secret = cfg_get_opap_secret(name, TAC_PLUS_RECURSE);
	    break;

	default:
	    data->status = TAC_PLUS_AUTHEN_STATUS_ERROR;
	    data->server_msg = tac_strdup("Illegal authentication type");
	    report(LOG_ERR, "%s: Illegal authentication type %d",
		   session.peer, data->type);
	    return(0);
	}

	if (!secret) {
	    data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;
	    data->server_msg = tac_strdup("No secret");
	    return(0);
	}

	p = tac_find_substring("cleartext ", secret);
	if (!p) {
	    /* Should never happen */
	    data->status = TAC_PLUS_AUTHEN_STATUS_ERROR;
	    data->server_msg = tac_strdup("Illegal secret format");
	    report(LOG_ERR, "%s: Illegal secret format %s",
		   session.peer, secret);
	    return(0);
	}

	data->server_data = tac_strdup(p);
	data->server_dlen = strlen(data->server_data);
	data->status = TAC_PLUS_AUTHEN_STATUS_PASS;
	if (expired == PW_EXPIRING) {
	    data->server_msg = tac_strdup("Secret will expire soon");
	}
	return(0);
    }
    /* never reached */
}
