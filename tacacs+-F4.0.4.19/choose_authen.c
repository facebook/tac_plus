/*
 * $Id: choose_authen.c,v 1.8 2009-03-18 18:59:17 heas Exp $
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

static int choose_login(struct authen_data *, struct authen_type *);
static int choose_sendpass(struct authen_data *, struct authen_type *);
static int choose_sendauth(struct authen_data *, struct authen_type *);

/*
 * Choose an authentication function. Return CHOOSE_OK if chosen,
 * CHOOSE_GETUSER if we need a username, CHOOSE_FAILED on failure
 */
int
choose_authen(struct authen_data *data, struct authen_type *type)
{
#ifdef SKEY
    char *cfg_passwd;
#endif
    char *name = data->NAS_id->username;

    switch (data->action) {
    case TAC_PLUS_AUTHEN_SENDPASS:
	return(choose_sendpass(data, type));

    case TAC_PLUS_AUTHEN_SENDAUTH:
	return(choose_sendauth(data, type));

    case TAC_PLUS_AUTHEN_LOGIN:
	/* For enabling, enable_fn handles everything. Must be minor
	 * version zero
	 */
	if (data->service == TAC_PLUS_AUTHEN_SVC_ENABLE) {
	    if (session.version != TAC_PLUS_VER_0) {
		/* must be version 0 */
		break;
	    }
#ifdef SKEY
	    if (name[0] == '\0')
		return(CHOOSE_GETUSER);
	    cfg_passwd = cfg_get_enable_secret(name, TAC_PLUS_RECURSE);
	    if (cfg_passwd != NULL && STREQ(cfg_passwd, "skey")) {
		type->authen_func = skey_fn;
		strcpy(type->authen_name, "skey_fn");
		return(CHOOSE_OK);
	    }
#endif
	    type->authen_func = enable_fn;
	    strcpy(type->authen_name, "enable_fn");
	    return(CHOOSE_OK);
	}
	return(choose_login(data, type));

    case TAC_PLUS_AUTHEN_CHPASS:
	/* we don't support chpass */
	return(CHOOSE_FAILED);

    default:
	break;
    }

    /* never heard of this lot */
    report(LOG_ERR, "%s: %s %s Illegal packet ver=%d action=%d type=%d",
	   session.peer,
	   session.port,
	   name ? name : "<unknown>",
	   session.version,
	   data->action,
	   type->authen_type);

    return(CHOOSE_FAILED);
}

/* Choose an authentication function for action == LOGIN, service != enable */
static int
choose_login(struct authen_data *data, struct authen_type *type)
{
    char *name = data->NAS_id->username;
    char *cfg_passwd;

    switch(type->authen_type) {
    case TAC_PLUS_AUTHEN_TYPE_ASCII:
	if (session.version != TAC_PLUS_VER_0) {
	    break;
	}

	if (!name[0]) {
	    /* request a user name if not already supplied */
	    return(CHOOSE_GETUSER);
	}

	/* Does this user require s/key? */
	cfg_passwd = cfg_get_login_secret(name, TAC_PLUS_RECURSE);
	if (cfg_passwd && STREQ(cfg_passwd, "skey")) {
	    if (debug & DEBUG_PASSWD_FLAG)
		report(LOG_DEBUG, "%s %s: user %s requires skey",
		       session.peer, session.port, name);
#ifdef SKEY
	    type->authen_func = skey_fn;
	    strcpy(type->authen_name, "skey_fn");
	    return(CHOOSE_OK);
#else /* SKEY */
	    report(LOG_ERR,
		   "%s %s: user %s s/key support has not been compiled in",
		   name ? name : "<unknown>",
		   session.peer, session.port);
	    return(CHOOSE_FAILED);
#endif	/* SKEY */
	}

	/* Not an skey user. Must be none, des, cleartext or file password */
	type->authen_func = default_fn;
	strcpy(type->authen_name, "default_fn");
	return(CHOOSE_OK);

    case TAC_PLUS_AUTHEN_TYPE_ARAP:
#ifndef ARAP_DES
	/*
	 * If we have no des code we can't do ARAP via SENDAUTH. We'll
	 * have to do it via SENDPASS. Return a down-rev reply
	 * packet and hope the NAS is smart enough to deal with it.
	 */
	session.version = TAC_PLUS_VER_0;
	report(LOG_ERR, "%s %s: user %s DES is unavailable",
	       name ? name : "<unknown>", session.peer, session.port);
	return(CHOOSE_FAILED);
#endif /* ARAP_DES */
	/* FALLTHROUGH */

#ifdef MSCHAP
    case TAC_PLUS_AUTHEN_TYPE_MSCHAP:
#ifndef MSCHAP_DES
	/*
	 * If we have no des code we can't do MSCHAP via LOGIN. We'll
	 * have to do it via SENDPASS. Return a down-rev reply
	 * packet and hope the NAS is smart enough to deal with it.
	 */
	session.version = TAC_PLUS_VER_0;
	report(LOG_ERR, "%s %s: user %s DES is unavailable",
	       name ? name : "<unknown>", session.peer, session.port);
	return(CHOOSE_FAILED);
#endif /* MSCHAP_DES */
	/* FALLTHROUGH */
#endif /* MSCHAP */

    case TAC_PLUS_AUTHEN_TYPE_PAP:
    case TAC_PLUS_AUTHEN_TYPE_CHAP:
	if (session.version == TAC_PLUS_VER_0) {
	    type->authen_func = default_v0_fn;
	    strcpy(type->authen_name, "default_v0_fn");
	    return(CHOOSE_OK);
	}

	/* Version 1 login/[pap|chap|arap].
	 * The username must in the initial START packet
	 */
	if (!name[0]) {
	    report(LOG_ERR, "%s %s: No user in START packet for PAP/CHAP/ARAP",
		   session.peer, session.port);
	    return(CHOOSE_FAILED);
	}
	type->authen_func = default_fn;
	strcpy(type->authen_name, "default_fn");
	return(CHOOSE_OK);

    default:
	break;
    }

    /* Illegal value combination */
    report(LOG_ERR, "%s: %s %s Illegal packet ver=%d action=%d type=%d",
	   session.peer,
	   session.port,
	   name ? name : "<unknown>",
	   session.version,
	   data->action,
	   type->authen_type);
    return(CHOOSE_FAILED);
}

static int
choose_sendauth(struct authen_data *data, struct authen_type *type)
{
    char *name = data->NAS_id->username;

    switch (type->authen_type) {
#ifdef MSCHAP
    case TAC_PLUS_AUTHEN_TYPE_MSCHAP:
#ifndef MSCHAP_DES
	/*
	 * If we have no des code we can't do MSCHAP via SENDAUTH. We'll
	 * have to do it via SENDPASS. Return a down-rev reply
	 * packet and hope the NAS is smart enough to deal with it.
	 */
	session.version = TAC_PLUS_VER_0;
	report(LOG_ERR, "%s %s: user %s DES is unavailable",
	       name ? name : "<unknown>", session.peer, session.port);
	return(CHOOSE_FAILED);
#endif /* MSCHAP_DES */
	/* FALLTHROUGH */
#endif /* MSCHAP */

    case TAC_PLUS_AUTHEN_TYPE_CHAP:
    case TAC_PLUS_AUTHEN_TYPE_PAP:
	/* Must be minor version 1 */
	if (session.version != TAC_PLUS_VER_1) {
	    break;
	}

	/* The start packet must contain the username */
	if (!name[0]) {
	    return(CHOOSE_FAILED);
	}
	type->authen_func = sendauth_fn;
	strcpy(type->authen_name, "sendauth_fn");
	return(CHOOSE_OK);

    default:
	break;
    }
    /* Illegal value combination */
    report(LOG_ERR, "%s: %s %s Illegal packet ver=%d action=%d type=%d",
	   session.peer,
	   session.port,
	   name ? name : "<unknown>",
	   session.version,
	   data->action,
	   type->authen_type);

    return(CHOOSE_FAILED);
}

/* Compatibility routine for (obsolete) minor version == 0 */
static int
choose_sendpass(struct authen_data *data, struct authen_type *type)
{
    char *name = data->NAS_id->username;

    switch (type->authen_type) {
    case TAC_PLUS_AUTHEN_TYPE_CHAP:
#ifdef MSCHAP
    case TAC_PLUS_AUTHEN_TYPE_MSCHAP:
#endif /* MSCHAP */
    case TAC_PLUS_AUTHEN_TYPE_PAP:
    case TAC_PLUS_AUTHEN_TYPE_ARAP:
	/* must be minor version 0 */
	if (TAC_PLUS_VER_0 != session.version) {
	    break;
	}

	/* We need a username */
	if (!name[0]) {
	    return(CHOOSE_GETUSER);
	}

	type->authen_func = sendpass_fn;
	strcpy(type->authen_name, "sendpass_fn");
	return(CHOOSE_OK);

    default:
	break;
    }

    /* Illegal value combination */
    report(LOG_ERR, "%s: %s %s Illegal packet ver=%d action=%d type=%d",
	   session.peer,
	   session.port,
	   name ? name : "<unknown>",
	   session.version,
	   data->action,
	   type->authen_type);

    return(CHOOSE_FAILED);
}
