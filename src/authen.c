/*
 * $Id: authen.c,v 1.13 2009-04-10 18:46:43 heas Exp $
 *
 * Copyright (c) 1995-1998 by Cisco systems, Inc.

 * Permission to use, copy, modify, and distribute this software for
 * any purpose and without fee is hereby granted, provided that this
 * copyright and permission notice appear on all copies of the
 * software and supporting documentation, the name of Cisco Systems,
 * Inc. not be used in advertising or publicity pertaining to
 * distribution of the program without specific prior permission, and
 * notice be given in supporting documentation that modification,
 * copying and distribution is by permission of Cisco Systems, Inc.

 * Cisco Systems, Inc. makes no representations about the suitability
 * of this software for any purpose.  THIS SOFTWARE IS PROVIDED ``AS
 * IS'' AND WITHOUT ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING,
 * WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
 * FITNESS FOR A PARTICULAR PURPOSE.
 */

#include "tac_plus.h"

static int choose();
static void authenticate();
static void do_start();

/*
 *  Come here when we receive an authentication START packet
 */
void
authen(u_char *pak)
{
    char msg[55];
    struct authen_start *start;
    HDR *hdr;

    hdr = (HDR *)pak;
    start = (struct authen_start *) (pak + TAC_PLUS_HDR_SIZE);

    if ((hdr->seq_no != 1) ||
	(ntohl(hdr->datalength) != TAC_AUTHEN_START_FIXED_FIELDS_SIZE +
	 start->user_len + start->port_len + start->rem_addr_len +
	 start->data_len)) {
	send_authen_error("Invalid AUTHEN/START packet (check keys)");
	return;
    }

    switch (start->action) {
    case TAC_PLUS_AUTHEN_LOGIN:
    case TAC_PLUS_AUTHEN_SENDAUTH:
    case TAC_PLUS_AUTHEN_SENDPASS:
	do_start(pak);
	return;
    default:
	sprintf(msg, "Invalid AUTHEN/START action=%d", start->action);
	send_authen_error(msg);
	return;
    }
}

/*
 * We have a valid AUTHEN/START packet. Fill out data structures and
 * attempt to authenticate.
 */
static void
do_start(u_char *pak)
{
    struct identity identity;
    struct authen_data authen_data;
    struct authen_type authen_type;
    struct authen_start *start;
    u_char *p;
    int ret;

    if (debug & DEBUG_PACKET_FLAG)
	report(LOG_DEBUG, "Authen Start request");

    /* fixed fields of this packet */
    start = (struct authen_start *)(pak + TAC_PLUS_HDR_SIZE);

    /* variable length data starts here */
    p = pak + TAC_PLUS_HDR_SIZE + TAC_AUTHEN_START_FIXED_FIELDS_SIZE;

    /* The identity structure */

    /* zero out identity struct so that all strings can be NULL terminated */
    memset(&identity, 0, sizeof(struct identity));

    identity.username = tac_make_string(p, (int)start->user_len);
    p += start->user_len;

    identity.NAS_name = tac_strdup(session.peer);
#ifdef ACLS
    identity.NAS_ip = tac_strdup(session.peerip);
#endif

    identity.NAS_port = tac_make_string(p, (int)start->port_len);
    p += start->port_len;

    if (start->port_len <= 0) {
	strcpy(session.port, "unknown-port");
    } else {
	strcpy(session.port, identity.NAS_port);
    }

    identity.NAC_address = tac_make_string(p, (int)start->rem_addr_len);
    p += start->rem_addr_len;

    identity.priv_lvl = start->priv_lvl;

    /* The authen_data structure */
    memset(&authen_data, 0, sizeof(struct authen_data));

    authen_data.NAS_id = &identity;
    authen_data.action = start->action;
    authen_data.service = start->service;
    authen_data.type = start->authen_type;
    authen_data.client_dlen = start->data_len;

    authen_data.client_data = tac_malloc(start->data_len);
    memcpy(authen_data.client_data, p, start->data_len);

    /* The authen_type structure */
    memset(&authen_type, 0, sizeof(struct authen_type));

    authen_type.authen_type = start->authen_type;

    /*
     * All data structures are now initialised. Now see if we can authenticate
     * this puppy. Begin by choosing a suitable authentication function to
     * call to actually do the work.
     */
    ret = choose(&authen_data, &authen_type);

    switch (ret) {
    case 1:
	/* A successful choice. Authenticate */
	authenticate(&authen_data, &authen_type);
	break;
    case 0:
	/* We lost our connection, aborted, or something dreadful happened */
	break;
    }

    /* free data structures */
    if (authen_data.server_msg) {
	free(authen_data.server_msg);
	authen_data.server_msg = NULL;
    }
    if (authen_data.server_data) {
	free(authen_data.server_data);
	authen_data.server_data = NULL;
    }
    if (authen_data.client_msg) {
	free(authen_data.client_msg);
	authen_data.client_msg = NULL;
    }
    if (authen_data.client_data) {
	free(authen_data.client_data);
	authen_data.client_data = NULL;
    }
    if (authen_data.method_data) {
	report(LOG_ERR, "%s: Method data not set to NULL after authentication",
	       session.peer);
    }
    free(identity.username);
    free(identity.NAS_name);
    free(identity.NAS_port);
    free(identity.NAC_address);
    return;
}

/*
 * Choose an authentication function. Return 1 if we successfully
 * chose a function.  0 if we couldn't make a choice for some reason
 */
static int
choose(struct authen_data *datap, struct authen_type *typep)
{
    int iterations = 0;
    int status;
    char *prompt;
    struct authen_cont *cont;
    u_char *reply;
    u_char *p;
    struct identity *identp;

    while (1) {
	/* check interation counter here */
	if (++iterations >= TAC_PLUS_MAX_ITERATIONS) {
	    report(LOG_ERR, "%s: %s Too many iterations for choose_authen",
		   session.peer,
		   session.port);
	    return(0);
	}
	status = choose_authen(datap, typep);

	if (status && (debug & DEBUG_PACKET_FLAG))
	    report(LOG_DEBUG, "choose_authen returns %d", status);

	switch (status) {
	case CHOOSE_BADTYPE: /* FIXME */
	default:
	    send_authen_error("choose_authen: unexpected failure return");
	    return(0);
	case CHOOSE_OK:
	    if (debug & DEBUG_PACKET_FLAG)
		report(LOG_DEBUG, "choose_authen chose %s", typep->authen_name);
	    return(1);
	case CHOOSE_FAILED:
	    send_authen_error("choose_authen: unacceptable authen method");
	    return(0);
	case CHOOSE_GETUSER:
	    /*
	     * respond with GETUSER containing an optional message from
	     * authen_data.server_msg.
	     */
	    datap->status = TAC_PLUS_AUTHEN_STATUS_GETUSER;
	    if (datap->service == TAC_PLUS_AUTHEN_SVC_LOGIN) {
		prompt = cfg_get_host_prompt(datap->NAS_id->NAS_ip);
		if (prompt == NULL && !STREQ(datap->NAS_id->NAS_name,
					     datap->NAS_id->NAS_ip)) {
		    prompt = cfg_get_host_prompt(datap->NAS_id->NAS_name);
		}

		if (prompt == NULL) {
		    prompt = "\nUser Access Verification\n\nUsername: ";
		}
	    } else {
		prompt = "Username: ";
	    }
	    send_authen_reply(TAC_PLUS_AUTHEN_STATUS_GETUSER, /* status */
			      prompt, /* msg */
			      strlen(prompt), /* msg_len */
			      datap->server_data,
			      datap->server_dlen,
			      0 /* flags */);

	    if (datap->server_data) {
		free(datap->server_data);
		datap->server_dlen = 0;
	    }
	    /* expect a CONT from the NAS */
	    reply = get_authen_continue();
	    if (reply == NULL) {
		/* Typically premature close of connection */
		report(LOG_ERR, "%s %s: Null reply packet, expecting CONTINUE",
		       session.peer, session.port);
		return(0);
	    }

	    cont = (struct authen_cont *)(reply + TAC_PLUS_HDR_SIZE);

	    if (cont->flags & TAC_PLUS_CONTINUE_FLAG_ABORT) {
		char buf[65537];
		buf[0] = '\0';
		session.aborted = 1;

		if (cont->user_data_len) {
		    /* An abort message exists. Log it */
		    p = reply + TAC_PLUS_HDR_SIZE +
			TAC_AUTHEN_CONT_FIXED_FIELDS_SIZE + cont->user_msg_len;

		    memcpy(buf, p, cont->user_data_len);
		    buf[cont->user_data_len] = '\0';
		}
		report(LOG_INFO, "%s %s: Login aborted by request -- msg: %s",
		       session.peer, session.port, buf);
		free(reply);
		return(0);
	    }

	    p = reply + TAC_PLUS_HDR_SIZE + TAC_AUTHEN_CONT_FIXED_FIELDS_SIZE;

	    identp = datap->NAS_id;

	    if (identp->username) {
		free(identp->username);
	    }
	    identp->username = tac_make_string(p, cont->user_msg_len);
	    free(reply);
	}
    }
    /* NOTREACHED */
}

/*
 * Perform authentication assuming we have successfully chosen an
 * authentication method
 */
static void
authenticate(struct authen_data *datap, struct authen_type *typep)
{
    int iterations = 0;
    u_char *reply, *p;
    struct authen_cont *cont;
    int (*func) ();

    if (debug & DEBUG_PACKET_FLAG)
	report(LOG_DEBUG, "Calling authentication function");

    func = typep->authen_func;

    if (!func) {
	send_authen_error("authenticate: cannot find function pointer");
	return;
    }

    while (1) {
	if (session.aborted)
	    return;

	if (++iterations >= TAC_PLUS_MAX_ITERATIONS) {
	    send_authen_error("Too many iterations while authenticating");
	    return;
	}

	if ((*func) (datap)) {
	    send_authen_error("Unexpected authentication function failure");
	    return;
	}

	switch (datap->status) {
	default:
	    send_authen_error("Illegal status value from authentication "
			      "function");
	    return;
	case TAC_PLUS_AUTHEN_STATUS_PASS:
	    /* A successful authentication */
	    send_authen_reply(TAC_PLUS_AUTHEN_STATUS_PASS,
			      datap->server_msg,
			      datap->server_msg ? strlen(datap->server_msg) : 0,
			      datap->server_data,
			      datap->server_dlen,
			      0);
	    return;
	case TAC_PLUS_AUTHEN_STATUS_ERROR:
	    /*
	     * never supposed to happen. reply with a server_msg if any, and
	     * bail out
	     */
	    send_authen_error(datap->server_msg ? datap->server_msg :
			    "authentication function: unspecified failure");
	    return;
	case TAC_PLUS_AUTHEN_STATUS_FAIL:
	    /* An invalid user/password combination */
	    send_authen_reply(TAC_PLUS_AUTHEN_STATUS_FAIL,
			      datap->server_msg,
			      datap->server_msg ? strlen(datap->server_msg) : 0,
			      NULL, 0, 0);
	    return;
	case TAC_PLUS_AUTHEN_STATUS_GETUSER:
	case TAC_PLUS_AUTHEN_STATUS_GETPASS:
	case TAC_PLUS_AUTHEN_STATUS_GETDATA:
	    /* ship GETPASS/GETDATA containing datap->server_msg to NAS. */
	    send_authen_reply(datap->status,
			      datap->server_msg,
			      datap->server_msg ? strlen(datap->server_msg) : 0,
			      datap->server_data,
			      datap->server_dlen,
			      datap->flags);

	    datap->flags = 0;

	    if (datap->server_msg) {
		free(datap->server_msg);
		datap->server_msg = NULL;
	    }
	    if (datap->server_data) {
		free(datap->server_data);
		datap->server_data = NULL;
	    }
	    if (datap->client_msg) {
		free(datap->client_msg);
		datap->client_msg = NULL;
	    }
	    reply = get_authen_continue();
	    if (!reply) {
		/* Typically due to a premature connection close */
		report(LOG_ERR, "%s %s: Null reply packet, expecting CONTINUE",
		       session.peer, session.port);

		/* Tell the authentication function it should clean up
		   any private data */

		datap->flags |= TAC_PLUS_CONTINUE_FLAG_ABORT;

		if (datap->method_data)
		    ((*func) (datap));

		datap->flags = 0;
		return;
	    }

	    cont = (struct authen_cont *) (reply + TAC_PLUS_HDR_SIZE);

	    if (cont->flags & TAC_PLUS_CONTINUE_FLAG_ABORT) {
		session.aborted = 1;

		/* Tell the authentication function to clean up
		   its private data, if there is any */

		datap->flags |= TAC_PLUS_CONTINUE_FLAG_ABORT;
		if (datap->method_data)
		    ((*func) (datap));
		datap->flags = 0;

		if (cont->user_data_len) {
		    /*
		     * An abort message exists. Create a null-terminated
		     * string for authen_data
		     */
		    datap->client_data = (char *)
			tac_malloc(cont->user_data_len + 1);

		    p = reply + TAC_PLUS_HDR_SIZE +
			TAC_AUTHEN_CONT_FIXED_FIELDS_SIZE + cont->user_msg_len;

		    memcpy(datap->client_data, p, cont->user_data_len);
		    datap->client_data[cont->user_data_len] = '\0';
		}

		free(reply);
		return;
	    }

	    p = reply + TAC_PLUS_HDR_SIZE + TAC_AUTHEN_CONT_FIXED_FIELDS_SIZE;

	    switch (datap->status) {
	    case TAC_PLUS_AUTHEN_STATUS_GETDATA:
	    case TAC_PLUS_AUTHEN_STATUS_GETPASS:
		/* A response to our GETDATA/GETPASS request. Create a
		 * null-terminated string for authen_data */
		datap->client_msg = (char *)tac_malloc(cont->user_msg_len + 1);
		memcpy(datap->client_msg, p, cont->user_msg_len);
		datap->client_msg[cont->user_msg_len] = '\0';
		free(reply);
		continue;
	    case TAC_PLUS_AUTHEN_STATUS_GETUSER:
	    default:
		report(LOG_ERR, "%s: authenticate: cannot happen",
		       session.peer);
		send_authen_error("authenticate: cannot happen");
		free(reply);
		return;
	    }
	}
	/* NOTREACHED */
    }
}
