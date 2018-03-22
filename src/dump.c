/*
 * $Id: dump.c,v 1.12 2009-03-18 21:09:26 heas Exp $
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

/* Routines for dumping packets to stderr */
char *
summarise_outgoing_packet_type(u_char *pak)
{
    HDR *hdr;
    struct authen_reply *authen;
    struct author_reply *author;
    char *p;

    hdr = (HDR *)pak;

    switch (hdr->type) {
    case TAC_PLUS_AUTHEN:
	authen = (struct authen_reply *) (pak + TAC_PLUS_HDR_SIZE);

	switch (authen->status) {
	case TAC_PLUS_AUTHEN_STATUS_PASS:
	    p = "AUTHEN/SUCCEED";
	    break;
	case TAC_PLUS_AUTHEN_STATUS_FAIL:
	    p = "AUTHEN/FAIL";
	    break;
	case TAC_PLUS_AUTHEN_STATUS_GETDATA:
	    p = "AUTHEN/GETDATA";
	    break;
	case TAC_PLUS_AUTHEN_STATUS_GETUSER:
	    p = "AUTHEN/GETUSER";
	    break;
	case TAC_PLUS_AUTHEN_STATUS_GETPASS:
	    p = "AUTHEN/GETPASS";
	    break;
	case TAC_PLUS_AUTHEN_STATUS_ERROR:
	    p = "AUTHEN/ERROR";
	    break;
	default:
	    p = "AUTHEN/UNKNOWN";
	    break;
	}
	break;

    case TAC_PLUS_AUTHOR:
	author = (struct author_reply *) (pak + TAC_PLUS_HDR_SIZE);
	switch (author->status) {
	case AUTHOR_STATUS_PASS_ADD:
	    p = "AUTHOR/PASS_ADD";
	    break;
	case AUTHOR_STATUS_FAIL:
	    p = "AUTHOR/FAIL";
	    break;
	case AUTHOR_STATUS_PASS_REPL:
	    p = "AUTHOR/PASS_REPL";
	    break;
	case AUTHOR_STATUS_ERROR:
	    p = "AUTHOR/ERROR";
	    break;
	default:
	    p = "AUTHOR/UNKNOWN";
	    break;
	}
	break;
    case TAC_PLUS_ACCT:
	p = "ACCT";
	break;
    default:
	p = "UNKNOWN";
	break;
    }
    return(p);
}

void
dump_header(u_char *pak)
{
    HDR *hdr;
    u_char *data;

    hdr = (HDR *)pak;

    report(LOG_DEBUG, "PACKET: key=%s", session.key ? session.key : "<NULL>");
    report(LOG_DEBUG, "version %d (0x%x), type %d, seq no %d, flags 0x%x",
	   hdr->version, hdr->version, hdr->type, hdr->seq_no, hdr->flags);
    report(LOG_DEBUG, "session_id %u (0x%x), Data length %d (0x%x)",
	   ntohl(hdr->session_id), ntohl(hdr->session_id),
	   ntohl(hdr->datalength), ntohl(hdr->datalength));

    report(LOG_DEBUG, "End header");

    if (debug & DEBUG_HEX_FLAG) {
	report(LOG_DEBUG, "Packet body hex dump:");
	data = (u_char *)(pak + TAC_PLUS_HDR_SIZE);
	report_hex(LOG_DEBUG, data, ntohl(hdr->datalength));
    }
}

/* Dump packets originated by a NAS */
void
dump_nas_pak(u_char *pak)
{
    struct authen_start *start;
    struct authen_cont *cont;
    struct author *author;
    struct acct *acct;
    int i, resid;
    HDR *hdr;
    u_char *p, *argsizep;
    int seq;

    dump_header(pak);

    hdr = (HDR *)pak;

    seq = hdr->seq_no;
    if (seq % 2 != 1) {
	report(LOG_DEBUG, "nas packets should be odd numbered seq=%d",
	       seq);
	exit(1);
    }

    resid = hdr->datalength;
    switch (hdr->type) {
    case TAC_PLUS_AUTHEN:
	start = (struct authen_start *) (pak + TAC_PLUS_HDR_SIZE);

	switch (hdr->seq_no) {
	case 1:
	    report(LOG_DEBUG, "type=AUTHEN/START, priv_lvl = %d",
		   start->priv_lvl);
	    if (resid < TAC_AUTHEN_START_FIXED_FIELDS_SIZE) {
		report(LOG_DEBUG, "Bad AUTHEN/START packet length %d", resid);
		return;
	    }
	    resid -= TAC_AUTHEN_START_FIXED_FIELDS_SIZE;

	    switch (start->action) {
	    case TAC_PLUS_AUTHEN_LOGIN:
		report(LOG_DEBUG, "action=login");
		break;
	    case TAC_PLUS_AUTHEN_CHPASS:
		report(LOG_DEBUG, "action=chpass");
		break;
	    case TAC_PLUS_AUTHEN_SENDPASS:
		report(LOG_DEBUG, "action=sendpass");
		break;
	    case TAC_PLUS_AUTHEN_SENDAUTH:
		report(LOG_DEBUG, "action=sendauth");
		break;
	    default:
		report(LOG_DEBUG, "action=UNKNOWN %d", start->action);
		break;
	    }

	    switch(start->authen_type) {
	    case TAC_PLUS_AUTHEN_TYPE_ASCII:
		report(LOG_DEBUG, "authen_type=ascii");
		break;
	    case TAC_PLUS_AUTHEN_TYPE_PAP:
		report(LOG_DEBUG, "authen_type=pap");
		break;
	    case TAC_PLUS_AUTHEN_TYPE_CHAP:
		report(LOG_DEBUG, "authen_type=chap");
		break;
	    case TAC_PLUS_AUTHEN_TYPE_ARAP:
		report(LOG_DEBUG, "authen_type=arap");
		break;
	    default:
		report(LOG_DEBUG, "authen_type=unknown %d", start->authen_type);
		break;
	    }

	    switch(start->service) {
	    case TAC_PLUS_AUTHEN_SVC_LOGIN:
		report(LOG_DEBUG, "service=login");
		break;
	    case TAC_PLUS_AUTHEN_SVC_ENABLE:
		report(LOG_DEBUG, "service=enable");
		break;
	    case TAC_PLUS_AUTHEN_SVC_PPP:
		report(LOG_DEBUG, "service=ppp");
		break;
	    case TAC_PLUS_AUTHEN_SVC_ARAP:
		report(LOG_DEBUG, "service=arap");
		break;
	    case TAC_PLUS_AUTHEN_SVC_PT:
		report(LOG_DEBUG, "service=pt");
		break;
	    case TAC_PLUS_AUTHEN_SVC_RCMD:
		report(LOG_DEBUG, "service=rcmd");
		break;
	    case TAC_PLUS_AUTHEN_SVC_X25:
		report(LOG_DEBUG, "service=x25");
		break;
	    case TAC_PLUS_AUTHEN_SVC_NASI:
		report(LOG_DEBUG, "service=nasi");
		break;
	    default:
		report(LOG_DEBUG, "service=unknown %d", start->service);
		break;
	    }

	    report(LOG_DEBUG, "user_len=%d port_len=%d (0x%x), rem_addr_len=%d"
		   " (0x%x)", start->user_len, start->port_len, start->port_len,
		   start->rem_addr_len, start->rem_addr_len);
	    report(LOG_DEBUG, "data_len=%d", start->data_len);
	    if (resid < (start->user_len + start->port_len +
			 start->rem_addr_len + start->data_len)) {
		report(LOG_DEBUG, "AUTHEN/START data length (%d) exceeds "
		       "packet length length %d", (start->user_len +
		       start->port_len + start->rem_addr_len + start->data_len),
		       resid);
		return;
	    }

	    /* start of variable length data is here */
	    p = pak + TAC_PLUS_HDR_SIZE + TAC_AUTHEN_START_FIXED_FIELDS_SIZE;

	    report(LOG_DEBUG, "User: ");
	    report_string(LOG_DEBUG, p, start->user_len);
	    p += start->user_len;

	    report(LOG_DEBUG, "port: ");
	    report_string(LOG_DEBUG, p, start->port_len);
	    p += start->port_len;

	    report(LOG_DEBUG, "rem_addr: ");
	    report_string(LOG_DEBUG, p, start->rem_addr_len);
	    p += start->rem_addr_len;

	    report(LOG_DEBUG, "data: ");
	    report_string(LOG_DEBUG, p, start->data_len);

	    report(LOG_DEBUG, "End packet");
	    return;

	default:
	    cont = (struct authen_cont *) (pak + TAC_PLUS_HDR_SIZE);
	    report(LOG_DEBUG, "type=AUTHEN/CONT");
	    if (resid < TAC_AUTHEN_CONT_FIXED_FIELDS_SIZE) {
		report(LOG_DEBUG, "Bad AUTHEN/CONT packet length %d", resid);
		return;
	    }
	    resid -= TAC_AUTHEN_CONT_FIXED_FIELDS_SIZE;

	    report(LOG_DEBUG, "user_msg_len %d (0x%x), user_data_len %d (0x%x)",
		   cont->user_msg_len, cont->user_msg_len,
		   cont->user_data_len, cont->user_data_len);
	    report(LOG_DEBUG, "flags=0x%x", cont->flags);
	    if (resid < (cont->user_msg_len + cont->user_data_len)) {
		report(LOG_DEBUG, "AUTHEN/CONT data length (%d) exceeds "
		       "packet length length %d", (cont->user_msg_len +
		       cont->user_data_len), resid);
		return;
	    }

	    /* start of variable length data is here */
	    p = pak + TAC_PLUS_HDR_SIZE +
		TAC_AUTHEN_CONT_FIXED_FIELDS_SIZE;

	    report(LOG_DEBUG, "User msg: ");
	    report_string(LOG_DEBUG, p, cont->user_msg_len);
	    p += cont->user_msg_len;

	    report(LOG_DEBUG, "User data: ");
	    report_string(LOG_DEBUG, p, cont->user_data_len);

	    report(LOG_DEBUG, "End packet");
	    return;
	}

    case TAC_PLUS_AUTHOR:
	author = (struct author *) (pak + TAC_PLUS_HDR_SIZE);

	report(LOG_DEBUG, "type=AUTHOR, priv_lvl=%d, authen=%d",
	       author->priv_lvl,
	       author->authen_type);
	if (resid < TAC_AUTHOR_REQ_FIXED_FIELDS_SIZE) {
	    report(LOG_DEBUG, "Bad AUTHOR packet length %d", resid);
	    return;
	}
	resid -= TAC_AUTHEN_CONT_FIXED_FIELDS_SIZE;

	switch(author->authen_method) {
	case AUTHEN_METH_NONE:
		report(LOG_DEBUG, "method=none");
		break;
	case AUTHEN_METH_KRB5:
		report(LOG_DEBUG, "method=krb5");
		break;
	case AUTHEN_METH_LINE:
		report(LOG_DEBUG, "method=line");
		break;
	case AUTHEN_METH_ENABLE:
		report(LOG_DEBUG, "method=enable");
		break;
	case AUTHEN_METH_LOCAL:
		report(LOG_DEBUG, "method=local");
		break;
	case AUTHEN_METH_TACACSPLUS:
		report(LOG_DEBUG, "method=tacacs+");
		break;
	case AUTHEN_METH_RCMD:
		report(LOG_DEBUG, "method=rcmd");
		break;
	default:
		report(LOG_DEBUG, "method=unknown %d", author->authen_method);
		break;
	}

	report(LOG_DEBUG, "svc=%d user_len=%d port_len=%d rem_addr_len=%d",
	       author->service, author->user_len,
	       author->port_len, author->rem_addr_len);
	report(LOG_DEBUG, "arg_cnt=%d", author->arg_cnt);
	if (resid < (author->service + author->user_len + author->port_len +
		     author->rem_addr_len)) {
	    report(LOG_DEBUG, "AUTHOR data length (%d) exceeds packet length "
		   "length %d", (author->service + author->user_len +
		   author->port_len + author->rem_addr_len), resid);
	    return;
	}

	/* variable length data start here */
	p = pak + TAC_PLUS_HDR_SIZE + TAC_AUTHOR_REQ_FIXED_FIELDS_SIZE;
	argsizep = p;
	p += author->arg_cnt;

	report(LOG_DEBUG, "User: ");
	report_string(LOG_DEBUG, p, author->user_len);
	p += author->user_len;

	report(LOG_DEBUG, "port: ");
	report_string(LOG_DEBUG, p, author->port_len);
	p += author->port_len;

	report(LOG_DEBUG, "rem_addr: ");
	report_string(LOG_DEBUG, p, author->rem_addr_len);
	p += author->rem_addr_len;

	for (i = 0; i < (int)author->arg_cnt; i++) {
	    report(LOG_DEBUG, "arg[%d]: size=%d ", i, *argsizep);
	    report_string(LOG_DEBUG, p, *argsizep);
	    p += *argsizep;
	    argsizep++;
	}
	break;

    case TAC_PLUS_ACCT:
	acct = (struct acct *) (pak + TAC_PLUS_HDR_SIZE);
	report(LOG_DEBUG, "ACCT, flags=0x%x method=%d priv_lvl=%d",
	       acct->flags, acct->authen_method, acct->priv_lvl);
	report(LOG_DEBUG, "type=%d svc=%d",
	       acct->authen_type, acct->authen_service);
	if (resid < TAC_ACCT_REQ_FIXED_FIELDS_SIZE) {
	    report(LOG_DEBUG, "Bad ACCT packet length %d", resid);
	    return;
	}
	resid -= TAC_ACCT_REQ_FIXED_FIELDS_SIZE;
	if (resid < (acct->user_len + acct->port_len + acct->rem_addr_len)) {
	    report(LOG_DEBUG, "AUTHOR data length (%d) exceeds packet length "
		   "%d", (acct->user_len + acct->port_len + acct->rem_addr_len),
		   resid);
	    return;
	}
	resid -= acct->user_len + acct->port_len + acct->rem_addr_len;
	report(LOG_DEBUG, "user_len=%d port_len=%d rem_addr_len=%d",
	       acct->user_len, acct->port_len, acct->rem_addr_len);
	report(LOG_DEBUG, "arg_cnt=%d", acct->arg_cnt);

	p = pak + TAC_PLUS_HDR_SIZE + TAC_ACCT_REQ_FIXED_FIELDS_SIZE;
	argsizep = p;
	p += acct->arg_cnt;

	report(LOG_DEBUG, "User: ");
	report_string(LOG_DEBUG, p, acct->user_len);
	p += acct->user_len;

	report(LOG_DEBUG, "port: ");
	report_string(LOG_DEBUG, p, acct->port_len);
	p += acct->port_len;

	report(LOG_DEBUG, "rem_addr: ");
	report_string(LOG_DEBUG, p, acct->rem_addr_len);
	p += acct->rem_addr_len;

	for (i = 0; i < (int)acct->arg_cnt; i++) {
	    report(LOG_DEBUG, "arg[%d]: size=%d ", i, *argsizep);
	    if (resid < 1 + *argsizep) {
		report(LOG_DEBUG, "ACCT arg %d data length (%d) exceeds packet "
		      "length %d", i, (1 + *argsizep), resid);
		return;
	    }
	    resid -= 1 + *argsizep;
	    report_string(LOG_DEBUG, p, *argsizep);
	    p += *argsizep;
	    argsizep++;
	}
	break;

    default:
	report(LOG_DEBUG, "dump_nas_pak: unrecognized header type %d",
	       hdr->type);
    }
    report(LOG_DEBUG, "End packet");
}

/* Dump packets originated by Tacacsd  */
void
dump_tacacs_pak(u_char *pak)
{
    struct authen_reply *authen;
    struct author_reply *author;
    struct acct_reply *acct;
    HDR *hdr;
    u_char *p, *argsizep;
    int i;
    int seq;

    dump_header(pak);

    hdr = (HDR *)pak;
    seq = hdr->seq_no;

    if (seq % 2 != 0) {
	report(LOG_ERR, "%s: Bad sequence number %d should be even",
	       session.peer, seq);
	tac_exit(1);
    }

    switch (hdr->type) {
    case TAC_PLUS_AUTHEN:
	authen = (struct authen_reply *) (pak + TAC_PLUS_HDR_SIZE);

	report(LOG_DEBUG, "type=AUTHEN status=%d (%s) flags=0x%x",
	       authen->status, summarise_outgoing_packet_type(pak),
	       authen->flags);

	report(LOG_DEBUG, "msg_len=%d, data_len=%d",
	       authen->msg_len, authen->data_len);

	/* start of variable length data is here */
	p = pak + TAC_PLUS_HDR_SIZE + TAC_AUTHEN_REPLY_FIXED_FIELDS_SIZE;

	report(LOG_DEBUG, "msg: ");
	report_string(LOG_DEBUG, p, authen->msg_len);
	p += authen->msg_len;

	report(LOG_DEBUG, "data: ");
	report_string(LOG_DEBUG, p, authen->data_len);

	report(LOG_DEBUG, "End packet");
	return;

    case TAC_PLUS_AUTHOR:
	author = (struct author_reply *) (pak + TAC_PLUS_HDR_SIZE);

	report(LOG_DEBUG, "type=AUTHOR/REPLY status=%d (%s) ",
	       author->status, summarise_outgoing_packet_type(pak));
	report(LOG_DEBUG, "msg_len=%d, data_len=%d arg_cnt=%d",
	       author->msg_len, author->data_len, author->arg_cnt);

	/* start of variable length data is here */
	p = pak + TAC_PLUS_HDR_SIZE + TAC_AUTHOR_REPLY_FIXED_FIELDS_SIZE;

	/* arg sizes come next */
	argsizep = p;

	p += author->arg_cnt;

	report(LOG_DEBUG, "msg: ");
	report_string(LOG_DEBUG, p, author->msg_len);
	p += author->msg_len;

	report(LOG_DEBUG, "data: ");
	report_string(LOG_DEBUG, p, author->data_len);
	p += author->data_len;

	/* args follow */
	for (i = 0; i < (int)author->arg_cnt; i++) {
	    int size = argsizep[i];

	    report(LOG_DEBUG, "arg[%d] size=%d ", i, size);
	    report_string(LOG_DEBUG, p, size);
	    p += size;
	}
	break;

    case TAC_PLUS_ACCT:
	acct = (struct acct_reply *) (pak + TAC_PLUS_HDR_SIZE);
	report(LOG_DEBUG, "ACCT/REPLY status=%d", acct->status);

	report(LOG_DEBUG, "msg_len=%d data_len=%d",
	       acct->msg_len, acct->data_len);

	p = pak + TAC_PLUS_HDR_SIZE + TAC_ACCT_REPLY_FIXED_FIELDS_SIZE;

	report(LOG_DEBUG, "msg: ");

	report_string(LOG_DEBUG, p, acct->msg_len);
	p += acct->msg_len;

	report(LOG_DEBUG, "data: ");
	report_string(LOG_DEBUG, p, acct->data_len);

	break;

    default:
	report(LOG_DEBUG, "dump_tacacs_pak: unrecognized header type %d",
	       hdr->type);
    }
    report(LOG_DEBUG, "End packet");
}

/* summarise packet types for logging routines. */
char *
summarise_incoming_packet_type(u_char *pak)
{
    HDR *hdr;
    char *p;

    hdr = (HDR *)pak;

    switch (hdr->type) {
    case TAC_PLUS_AUTHEN:
	switch (hdr->seq_no) {
	case 1:
	    p = "AUTHEN/START";
	    break;
	default:
	    p = "AUTHEN/CONT";
	    break;
	}
	return(p);

    case TAC_PLUS_AUTHOR:
	p = "AUTHOR";
	break;
    case TAC_PLUS_ACCT:
	p = "ACCT";
	break;
    default:
	p = "UNKNOWN";
	break;
    }
    return(p);
}
