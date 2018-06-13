/*
 * $Id: author.c,v 1.10 2009-03-17 18:31:27 heas Exp $
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

/*
 *  Come here when we receive an authorization START packet
 */
void
author(u_char *pak)
{
    HDR *hdr;
    struct author *apak;
    struct identity identity;
#ifdef ACLS
    struct authen_data authen_data;
#endif
    struct author_data author_data;
    u_char *p;
    u_char *argsizep;
    char **cmd_argp;
    int i, len;

    if (debug & DEBUG_AUTHOR_FLAG)
	report(LOG_DEBUG, "Start authorization request");

    hdr = (HDR *)pak;
    apak = (struct author *)(pak + TAC_PLUS_HDR_SIZE);

    /* Do some sanity checks */
    if (hdr->seq_no != 1) {
	send_error_reply(TAC_PLUS_AUTHOR, NULL);
	return;
    }

    /* Check if there's at least sizeof(struct author) of useful data */
    if (ntohl(hdr->datalength) < TAC_AUTHOR_REQ_FIXED_FIELDS_SIZE) {
	report(LOG_ERR, "%s: author minimum payload length: %zu, got: %u",
	       session.peer, TAC_AUTHOR_REQ_FIXED_FIELDS_SIZE,
	       ntohl(hdr->datalength));
	send_error_reply(TAC_PLUS_AUTHOR, NULL);
	return;
    }
  
    /* arg counts start here */
    p = pak + TAC_PLUS_HDR_SIZE + TAC_AUTHOR_REQ_FIXED_FIELDS_SIZE;

    /* Length checks */
    len = TAC_AUTHOR_REQ_FIXED_FIELDS_SIZE;
    len += apak->user_len + apak->port_len + apak->rem_addr_len + apak->arg_cnt;
  
    /* Is there enough space for apak->arg_cnt arguments? */
    if (ntohl(hdr->datalength) <
	(TAC_AUTHOR_REQ_FIXED_FIELDS_SIZE + apak->arg_cnt)) {
	report(LOG_ERR, "%s: author minimum payload length: %zu, got: %u",
	       session.peer, TAC_AUTHOR_REQ_FIXED_FIELDS_SIZE + apak->arg_cnt,
	       ntohl(hdr->datalength));
	send_error_reply(TAC_PLUS_AUTHOR, NULL);
	return;
    }

    for (i = 0; i < (int)apak->arg_cnt; i++) {
	len += p[i];
    }

    if (len != ntohl(hdr->datalength)) {
	send_error_reply(TAC_PLUS_AUTHOR, NULL);
	return;
    }

    /* start of variable length data is here */
    p = pak + TAC_PLUS_HDR_SIZE + TAC_AUTHOR_REQ_FIXED_FIELDS_SIZE;

    /* arg length data starts here */
    argsizep = p;

    p += apak->arg_cnt;

    memset(&author_data, 0, sizeof(struct author_data));

    /* The identity structure */

    /* zero out identity struct */
    memset(&identity, 0, sizeof(struct identity));
    identity.username = tac_make_string(p, (int)apak->user_len);
    p += apak->user_len;

    identity.NAS_name = tac_strdup(session.peer);
#ifdef ACLS
    identity.NAS_ip = tac_strdup(session.peerip);
#endif

    identity.NAS_port = tac_make_string(p, (int)apak->port_len);
    p += apak->port_len;
    if (apak->port_len <= 0) {
	strcpy(session.port, "unknown-port");
    } else {
	strcpy(session.port, identity.NAS_port);
    }

    identity.NAC_address = tac_make_string(p, (int)apak->rem_addr_len);
    p += apak->rem_addr_len;

    identity.priv_lvl = apak->priv_lvl;

    /* The author_data structure */

    author_data.id = &identity;	/* user id */

    /* FIXME: validate these fields */
    author_data.authen_method = apak->authen_method;
    author_data.authen_type = apak->authen_type;
    author_data.service = apak->service;
    author_data.num_in_args = apak->arg_cnt;

    /* Space for args + NULL */
    cmd_argp = (char **)tac_malloc(apak->arg_cnt * sizeof(char *));

    /* p points to the start of args. Step thru them making strings */
    for (i = 0; i < (int)apak->arg_cnt; i++) {
	cmd_argp[i] = tac_make_string(p, *argsizep);
	p += *argsizep++;
    }

    author_data.input_args = cmd_argp;	/* input command arguments */

#ifdef ACLS
    authen_data.NAS_id = &identity;
    if (verify_host(author_data.id->username, &authen_data, S_acl,
		    TAC_PLUS_RECURSE) != S_permit) {
	author_data.status = AUTHOR_STATUS_FAIL;
    } else
#endif
	if (do_author(&author_data)) {
	    report(LOG_ERR, "%s: do_author returned an error", session.peer);
	    send_author_reply(AUTHOR_STATUS_ERROR,
			      author_data.msg, author_data.admin_msg,
			      author_data.num_out_args,
			      author_data.output_args);
	    return;
        }

    /* Send a reply packet */
    send_author_reply(author_data.status, author_data.msg,
		      author_data.admin_msg, author_data.num_out_args,
		      author_data.output_args);

    if (debug)
	report(LOG_INFO, "authorization query for '%s' %s from %s %s",
	       author_data.id->username && author_data.id->username[0] ?
	       author_data.id->username : "unknown",
	       author_data.id->NAS_port && author_data.id->NAS_port[0] ?
	       author_data.id->NAS_port : "unknown",
	       session.peer,
	       (author_data.status == AUTHOR_STATUS_PASS_ADD ||
		author_data.status == AUTHOR_STATUS_PASS_REPL) ?
	       "accepted" : "rejected");

    /* free the input args */
    if (author_data.input_args) {
	for (i = 0; i < author_data.num_in_args; i++)
	    free(author_data.input_args[i]);

	free(author_data.input_args);
	author_data.input_args = NULL;
    }

    /* free the output args */
    if (author_data.output_args) {
	for (i = 0; i < author_data.num_out_args; i++)
	    free(author_data.output_args[i]);

	free(author_data.output_args);
	author_data.output_args = NULL;
    }

    if (author_data.msg)
	free(author_data.msg);

    if (author_data.admin_msg)
	free(author_data.admin_msg);

    free(identity.username);
    free(identity.NAS_name);
#ifdef ACLS
    free(identity.NAS_ip);
#endif
    free(identity.NAS_port);
    free(identity.NAC_address);
}
