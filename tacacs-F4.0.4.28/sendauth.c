/*
 * $Id: sendauth.c,v 1.7 2009-03-17 18:40:20 heas Exp $
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
#include "md5.h"

static int do_sendauth_fn();
static void outbound_chap();
#ifdef MSCHAP
static void outbound_mschap();
#endif /* MSCHAP */
void outbound_pap();

int
sendauth_fn(struct authen_data *data)
{
    int status;
    char *name, *p;

    status = 0;
    name = data->NAS_id->username;

    if (STREQ(name, DEFAULT_USERNAME)) {
	/* This username is only valid for authorization */
	data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;
    } else {
	status = do_sendauth_fn(data);
    }

    if (debug) {
	switch (data->type) {
	case TAC_PLUS_AUTHEN_TYPE_CHAP:
	    p = "chap";
	    break;

#ifdef MSCHAP
	case TAC_PLUS_AUTHEN_TYPE_MSCHAP:
	    p = "ms-chap";
	    break;
#endif /* MSCHAP */

	case TAC_PLUS_AUTHEN_TYPE_PAP:
	    p = "pap";
	    break;

	default:
	    p = "unknown";
	    break;
	}

	report(LOG_INFO, "%s-sendauth query for '%s' %s from %s %s",
	       p,
	       name && name[0] ? name : "unknown",
	       session.peer, session.port,
	       (data->status == TAC_PLUS_AUTHEN_STATUS_PASS) ?
	       "accepted" : "rejected");
    }
    return(status);
}

/*
 * For PAP we need to supply the outgoing PAP cleartext password.
 * from the config file.
 *
 * For CHAP, we expect an id and a challenge. We will return an MD5 hash
 * if we're successful,
 *
 * Return 0 if data->status is valid, otherwise 1
 */
static int
do_sendauth_fn(struct authen_data *data)
{
    char *name, *exp_date;

    data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;

    /* We must have a username */
    if (!data->NAS_id->username[0]) {
	/* Missing username is a gross error */
	data->status = TAC_PLUS_AUTHEN_STATUS_ERROR;
	data->server_msg = tac_strdup("No username supplied");
	report(LOG_ERR, "%s: No username for sendauth_fn", session.peer);
	return(0);
    }
    name = data->NAS_id->username;

    switch (data->type) {
    case TAC_PLUS_AUTHEN_TYPE_CHAP:
	outbound_chap(data);
	break;

#ifdef MSCHAP
    case TAC_PLUS_AUTHEN_TYPE_MSCHAP:
	outbound_mschap(data);
	break;
#endif /* MSCHAP */

    case TAC_PLUS_AUTHEN_TYPE_PAP:
	outbound_pap(data);
	break;

    default:
	data->status = TAC_PLUS_AUTHEN_STATUS_ERROR;
	report(LOG_ERR, "%s %s: %s Illegal data type for sendauth_fn",
	       session.peer, session.port, name);
	return(0);
    }

    exp_date = cfg_get_expires(name, TAC_PLUS_RECURSE);
    set_expiration_status(exp_date, data);
    return(0);
}

void
outbound_pap(struct authen_data *data)
{
    char *secret, *p, *name;

    name = data->NAS_id->username;

    /* We must have a username */
    if (!name) {
	data->status = TAC_PLUS_AUTHEN_STATUS_ERROR;
	return;
    }

    /* Return her secret outbound PAP info */
    secret = cfg_get_opap_secret(name, TAC_PLUS_RECURSE);
    if (!secret) {
	if (debug & DEBUG_AUTHEN_FLAG) {
	    report(LOG_ERR, "%s %s: No opap secret for %s",
		   session.peer, session.port, name);
	}
	data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;
	return;
    }

    p = tac_find_substring("cleartext ", secret);
    if (!p) {
	/* Should never happen */
	data->status = TAC_PLUS_AUTHEN_STATUS_ERROR;
	report(LOG_ERR, "%s %s: Illegal opap secret format %s",
	       session.peer, session.port, secret);
	return;
    }

    data->server_data = tac_strdup(p);
    data->server_dlen = strlen(data->server_data);
    data->status = TAC_PLUS_AUTHEN_STATUS_PASS;
}

static void
outbound_chap(struct authen_data *data)
{
    char *name, *secret, *chal, digest[TAC_MD5_DIGEST_LEN];
    char *p;
    u_char *mdp;
    char id;
    int chal_len, inlen;
    MD5_CTX mdcontext;

    name = data->NAS_id->username;

    if (!name) {
	report(LOG_ERR, "%s %s: no username for outbound_chap",
	       session.peer, session.port);
	data->status = TAC_PLUS_AUTHEN_STATUS_ERROR;
	return;
    }

    id = data->client_data[0];

    chal_len = data->client_dlen - 1;
    if (chal_len < 0) {
	data->status = TAC_PLUS_AUTHEN_STATUS_ERROR;
	return;
    }

    if (debug & DEBUG_AUTHEN_FLAG) {
	report(LOG_DEBUG, "%s %s: user %s, id=%d chal_len=%d",
	       session.peer, session.port, name, (int)id, chal_len);
    }

    /* Assume failure */
    data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;

    /* Get the secret */
    secret = cfg_get_chap_secret(name, TAC_PLUS_RECURSE);

    /* If there is no chap password for this user, see if there is
       a global password for her that we can use */
    if (!secret) {
	secret = cfg_get_global_secret(name, TAC_PLUS_RECURSE);
    }

    if (!secret) {
	/* No secret. Fail */
	if (debug & DEBUG_AUTHEN_FLAG) {
	    report(LOG_DEBUG, "%s %s: No chap or global secret for %s",
		   session.peer, session.port, name);
	}
	data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;
	return;
    }


    p = tac_find_substring("cleartext ", secret);
    if (!p) {
	/* Should never happen */
	data->status = TAC_PLUS_AUTHEN_STATUS_ERROR;
	report(LOG_ERR, "%s %s: Illegal opap secret format %s",
	       session.peer, session.port, secret);
	return;
    }
    secret = p;

    /*
     * We now have the secret, the id, and the challenge value.
     * Put them all together, and run them through the MD5 digest
     * algorithm. */

    inlen = sizeof(u_char) + strlen(secret) + chal_len;
    mdp = (u_char *)tac_malloc(inlen);
    mdp[0] = id;
    memcpy(&mdp[1], secret, strlen(secret));
    chal = data->client_data + 1;
    memcpy(mdp + strlen(secret) + 1, chal, chal_len);
    MD5Init(&mdcontext);
    MD5Update(&mdcontext, mdp, inlen);
    MD5Final((u_char *)digest, &mdcontext);
    free(mdp);

    /*
     * Now return the calculated response value */

    data->server_data = tac_malloc(TAC_MD5_DIGEST_LEN);
    memcpy(data->server_data, digest, TAC_MD5_DIGEST_LEN);
    data->server_dlen = TAC_MD5_DIGEST_LEN;

    data->status = TAC_PLUS_AUTHEN_STATUS_PASS;
}

#ifdef MSCHAP

static void
outbound_mschap(struct authen_data *data)
{
    char *name, *secret, *chal;
    char *p;
    char id;
    int chal_len;

    name = data->NAS_id->username;

    if (!name) {
	report(LOG_ERR, "%s %s: no username for outbound_mschap",
	       session.peer, session.port);
	data->status = TAC_PLUS_AUTHEN_STATUS_ERROR;
	return;
    }

    id = data->client_data[0];

    chal_len = data->client_dlen - 1;
    if (data->client_dlen <= 2) {
	data->status = TAC_PLUS_AUTHEN_STATUS_ERROR;
	return;
    }

    if (debug & DEBUG_AUTHEN_FLAG) {
	report(LOG_DEBUG, "%s %s: user %s, id=%d chal_len=%d",
	       session.peer, session.port, name, (int)id, chal_len);
    }

    /* Assume failure */
    data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;

    /* Get the secret */
    secret = cfg_get_mschap_secret(name, TAC_PLUS_RECURSE);

    /* If there is no chap password for this user, see if there is
       a global password for her that we can use */
    if (!secret) {
	secret = cfg_get_global_secret(name, TAC_PLUS_RECURSE);
    }

    if (!secret) {
	/* No secret. Fail */
	if (debug & DEBUG_AUTHEN_FLAG) {
	    report(LOG_DEBUG, "%s %s: No ms-chap or global secret for %s",
		   session.peer, session.port, name);
	}
	data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;
	return;
    }

    p = tac_find_substring("cleartext ", secret);
    if (!p) {
	/* Should never happen */
	data->status = TAC_PLUS_AUTHEN_STATUS_ERROR;
	report(LOG_ERR, "%s %s: Illegal ms-chap secret format %s",
	       session.peer, session.port, secret);
	return;
    }
    secret = p;

    /*
     * We now have the secret, the id, and the challenge value.
     * Put them all together, and run them through the MD4 digest
     * algorithm. */

    chal = data->client_data + 1;

    /*
     * Now return the calculated response value */

    data->server_data = tac_malloc(MSCHAP_DIGEST_LEN);

    mschap_lmchallengeresponse(chal,secret,&data->server_data[0]);
    mschap_ntchallengeresponse(chal,secret,&data->server_data[24]);

    data->server_data[48] = 1; /* Mark it to use the NT response*/
    data->server_dlen = MSCHAP_DIGEST_LEN;

    data->status = TAC_PLUS_AUTHEN_STATUS_PASS;
}

#endif /* MSCHAP */
