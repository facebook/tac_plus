/*
 * $Id: acct.c,v 1.11 2009-04-21 15:59:25 heas Exp $
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
 *  Come here when we receive an Start Accounting packet
 */
static void account(u_char *);

void
accounting(u_char *pak)
{
    struct acct *acct_pak;
    u_char *p;
    HDR *hdr;
    int i, len;

    if (debug & DEBUG_ACCT_FLAG)
	report(LOG_DEBUG, "Start accounting request");

    hdr = (HDR *)pak;
    acct_pak = (struct acct *)(pak + TAC_PLUS_HDR_SIZE);

    /* Do some sanity checking on the packet */
    /* Check if there's at least sizeof(struct acct) of useful data */
    if (ntohl(hdr->datalength) < TAC_ACCT_REQ_FIXED_FIELDS_SIZE) {
	report(LOG_ERR, "%s: acct minimum payload length: %zu, got: %u",
	       session.peer, TAC_ACCT_REQ_FIXED_FIELDS_SIZE,
	       ntohl(hdr->datalength));
	send_error_reply(TAC_PLUS_ACCT, NULL);
	return;
    }

    /* arg counts start here */
    p = pak + TAC_PLUS_HDR_SIZE + TAC_ACCT_REQ_FIXED_FIELDS_SIZE;

    /* Length checks */
    len = TAC_ACCT_REQ_FIXED_FIELDS_SIZE;
    len += acct_pak->user_len + acct_pak->port_len +
	   acct_pak->rem_addr_len + acct_pak->arg_cnt;

    /* Is there enough space for acct_pak->length arguments */
    if (ntohl(hdr->datalength) <
	(TAC_ACCT_REQ_FIXED_FIELDS_SIZE + acct_pak->arg_cnt)) {
	report(LOG_ERR, "%s: acct minimum payload: %zu, got: %u",
	       session.peer, TAC_ACCT_REQ_FIXED_FIELDS_SIZE + acct_pak->arg_cnt,
	       ntohl(hdr->datalength));
	send_error_reply(TAC_PLUS_ACCT, NULL);
	return;
    }

    for (i = 0; i < (int)acct_pak->arg_cnt; i++) {
	len += p[i];
    }

    if (len != ntohl(hdr->datalength)) {
	send_error_reply(TAC_PLUS_ACCT, NULL);
	return;
    }

    account(pak);
}

static void
account(u_char *pak)
{
    struct acct *acct_pak;
    u_char *p, *argsizep;
    struct acct_rec rec;
    struct identity identity;
    char **cmd_argp;
    int i, errors = 0, status;

    acct_pak = (struct acct *)(pak + TAC_PLUS_HDR_SIZE);

    /* Fill out accounting record structure */
    memset(&rec, 0, sizeof(struct acct_rec));

    if (acct_pak->flags & TAC_PLUS_ACCT_FLAG_WATCHDOG)
	rec.acct_type = ACCT_TYPE_UPDATE;
    if (acct_pak->flags & TAC_PLUS_ACCT_FLAG_START)
	rec.acct_type = ACCT_TYPE_START;
    if (acct_pak->flags & TAC_PLUS_ACCT_FLAG_STOP)
	rec.acct_type = ACCT_TYPE_STOP;

    rec.authen_method  = acct_pak->authen_method;
    rec.authen_type    = acct_pak->authen_type;
    rec.authen_service = acct_pak->authen_service;

    /* start of variable length data is here */
    p = pak + TAC_PLUS_HDR_SIZE + TAC_ACCT_REQ_FIXED_FIELDS_SIZE;

    /* skip arg cnts */
    p += acct_pak->arg_cnt;

    /* zero out identity struct */
    memset(&identity, 0, sizeof(struct identity));

    identity.username = tac_make_string(p, (int)acct_pak->user_len);
    p += acct_pak->user_len;

    identity.NAS_name = tac_strdup(session.peer);

    identity.NAS_port = tac_make_string(p, (int)acct_pak->port_len);
    p += acct_pak->port_len;
    if (acct_pak->port_len <= 0) {
	strcpy(session.port, "unknown-port");
    } else {
	strcpy(session.port, identity.NAS_port);
    }

    identity.NAC_address = tac_make_string(p, (int)acct_pak->rem_addr_len);
    p += acct_pak->rem_addr_len;

    identity.priv_lvl = acct_pak->priv_lvl;

    rec.identity = &identity;

    /* Now process cmd args */
    argsizep = pak + TAC_PLUS_HDR_SIZE + TAC_ACCT_REQ_FIXED_FIELDS_SIZE;

    cmd_argp = (char **)tac_malloc(acct_pak->arg_cnt * sizeof(char *));

    for (i = 0; i < (int)acct_pak->arg_cnt; i++) {
	cmd_argp[i] = tac_make_string(p, *argsizep);
	p += *argsizep++;
    }

    rec.args = cmd_argp;
    rec.num_args = acct_pak->arg_cnt;

#ifdef MAXSESS
    /* Tally for MAXSESS counting */
    loguser(&rec);
#endif

    /* Do accounting */
    if (wtmpfile)
	errors = do_wtmp(&rec);
    if (session.acctfile != NULL)
	errors += do_acct_file(&rec);
    if (session.flags & SESS_FLAG_ACCTSYSL)
	errors += do_acct_syslog(&rec);

    if (errors) {
	status = TAC_PLUS_ACCT_STATUS_ERROR;
    } else {
	status = TAC_PLUS_ACCT_STATUS_SUCCESS;
    }
    send_acct_reply(status, rec.msg, rec.admin_msg);

    free(identity.username);
    free(identity.NAS_name);
    free(identity.NAS_port);
    free(identity.NAC_address);

    for (i = 0; i < (int)acct_pak->arg_cnt; i++) {
	free(cmd_argp[i]);
    }
    free(cmd_argp);

    if (rec.msg)
	free(rec.msg);
    if (rec.admin_msg)
	free(rec.admin_msg);
}
