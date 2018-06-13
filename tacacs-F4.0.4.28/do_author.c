/*
 * $Id: do_author.c,v 1.14 2009-03-17 18:38:12 heas Exp $
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
#include <regex.h>
#ifndef REG_OK
# ifdef REG_NOERROR
#  define REG_OK REG_NOERROR
# else
#  define REG_OK 0
# endif
#endif

static int arg_ok(char *);
static char *assemble_args(struct author_data *);
static int authorize_cmd(char *, char *, struct author_data *);
static int authorize_exec(char *, struct author_data *);
static int authorize_svc(char *, int, char *, char *, struct author_data *);
static int get_nas_svc(struct author_data *, char **, char **, char **);
static int is_separator(char);
static int mandatory(char *);
static int match_attrs(char *, char *);
static int match_values(char *, char *);
static int optional(char *);
static void post_authorization(char *, struct author_data *);
static int ppp_lcp_allowed(int, char *, char *);
static int pre_authorization(char *, struct author_data *);
static char *value(char *);


/* Return 0 is data->status is valid */
int
do_author(struct author_data *data)
{
    char *username = data->id->username;
    int status;
    int svc;
    char *cmd, *protocol, *svcname;

    status = 0;
    protocol = NULL;

    data->status = AUTHOR_STATUS_FAIL;	/* for safety */

    data->output_args = NULL;
    data->num_out_args = 0;

    if (debug & DEBUG_AUTHOR_FLAG)
	report(LOG_DEBUG, "do_author: user='%s'", username);

    if (!cfg_user_exists(username) && cfg_user_exists(DEFAULT_USERNAME)) {
	if (debug & DEBUG_AUTHOR_FLAG) {
	    report(LOG_DEBUG, "Authorizing user '%s' instead of '%s'",
		   DEFAULT_USERNAME, username);
	}
	username = DEFAULT_USERNAME;
    }

    /* See if there's a program defined which will do authorization for us */
    if (pre_authorization(username, data))
	return(0);

    /*
     * Decide what kind of authorization request this is. Currently
     * one of: exec, cmd, slip, arap, ppp or <string>
     *
     * If it's a command typed to the exec, return its text in cmd.
     *
     * If it's a ppp request, return the protocol name in protocol.
     */
    svc = get_nas_svc(data, &cmd, &protocol, &svcname);

    if (!svc) {
	/* if we can't identify the service in the request it's an error */
	data->status = AUTHOR_STATUS_ERROR;
	data->admin_msg =
	tac_strdup("No identifiable service/protocol in authorization request");
	if (debug & DEBUG_AUTHOR_FLAG) {
	    report(LOG_DEBUG, "user %s %s", username, data->admin_msg);
	}
	return(0);
    }

    if (debug & DEBUG_AUTHOR_FLAG)
	report(LOG_DEBUG, "user '%s' found", username);

#ifdef MAXSESS
    /* Never permit if they're going over their session limit */
    switch (svc) {
    case N_svc_arap:
    case N_svc_ppp:
    case N_svc_slip:
    case N_svc_exec:
/*    case N_svc: */
	if (maxsess_check_count(username, data)) {
	    return(0);
	}

    default:
	break;
    }
#endif /* MAXSESS */

    switch(svc) {
/*  XXX
    default:
	report(LOG_ERR, "%s: Bad service type %d", session.peer, svc);
	data->status = AUTHOR_STATUS_FAIL;
	return(0);*/

    case N_svc_cmd:
	/* A command authorisation request */
	status = authorize_cmd(username, cmd, data);
	break;

    case N_svc_exec:
	if (authorize_exec(username, data))
	    return(0);
	/* FALLTHRU */

    case N_svc_arap:
    case N_svc_ppp:
    case N_svc_slip:
	status = authorize_svc(username, svc, protocol, NULL, data);
	break;

    case N_svc:
	status = authorize_svc(username, svc, protocol, svcname, data);
	break;
    }

    post_authorization(username, data);
    return(status);
}

/*
 * If an before-authorization program has been specified, call it.
 *
 * A return value of 1 means no further authorization is required
 */
static int
pre_authorization(char *username, struct author_data *data)
{
    int status;
    char **out_args;
    int out_cnt, i;
    char *cmd;
    char error_str[255];
    int error_len = 255;

    out_cnt = 0;
    out_args = NULL;

    /*
     * If a before-authorization program exists, call it to see how to
     * proceed
     */
    cmd = cfg_get_pvalue(username, TAC_IS_USER,
			 S_before, TAC_PLUS_RECURSE);
    if (!cmd)
	return(0);

    if (debug & DEBUG_AUTHOR_FLAG)
	report(LOG_DEBUG, "Before authorization call: %s", cmd);

    status = call_pre_process(cmd, data, &out_args, &out_cnt, error_str,
			      error_len);

    switch (status) {
    default:
	if (debug & DEBUG_AUTHOR_FLAG)
	    report(LOG_DEBUG, "cmd %s returns %d (unrecognised value)",
		   cmd, status);

	data->status = AUTHOR_STATUS_ERROR;
	data->admin_msg =
	    tac_strdup("Illegal return status from pre-authorization command");
	data->msg = tac_strdup(error_str);
	data->num_out_args = 0;
	data->output_args = NULL;
	/* throw away out_args */
	for (i = 0; i < out_cnt; i++) {
	    free(out_args[i]);
	}
	if (out_args) {
	    free(out_args);
	}
	return(1);

    case 0: /* Permit */
	if (debug & DEBUG_AUTHOR_FLAG)
	    report(LOG_DEBUG, "cmd %s returns 0 (unconditional permit)", cmd);

	data->status = AUTHOR_STATUS_PASS_ADD;
	data->num_out_args = 0;
	data->output_args = NULL;

	/* throw away out_args */
	for (i = 0; i < out_cnt; i++) {
	    free(out_args[i]);
	}
	if (out_args) {
	    free(out_args);
	}
	return(1);

    case 1: /* Deny */
	if (debug & DEBUG_AUTHOR_FLAG)
	    report(LOG_DEBUG, "cmd %s returns %d (unconditional deny)",
		   cmd, status);

	data->status = AUTHOR_STATUS_FAIL;
	data->msg = tac_strdup(error_str);
	data->num_out_args = 0;
	data->output_args = NULL;

	/* throw away out_args */
	for (i = 0; i < out_cnt; i++) {
	    free(out_args[i]);
	}
	if (out_args) {
	    free(out_args);
	}
	return(1);

    case 2: /* Use replacement AV pairs from program as final result */
	if (debug & DEBUG_AUTHOR_FLAG) {
	    report(LOG_DEBUG, "cmd %s returns %d (permitted, args replaced)",
		   cmd, status);
	    for (i = 0; i < out_cnt; i++)
		report(LOG_DEBUG, "%s", out_args[i]);
	}

	/* and install the new set of AV pairs as output */
	data->output_args = out_args;
	data->num_out_args = out_cnt;
	data->status = AUTHOR_STATUS_PASS_REPL;
	return(1); /* no more processing required */

    case 3: /* deny, but return attributes and server-msg to NAS */
	if (debug & DEBUG_AUTHOR_FLAG) {
	    report(LOG_DEBUG, "cmd %s returns %d (deny, args replaced)",
		   cmd, status);
	    for (i = 0; i < out_cnt; i++)
		report(LOG_DEBUG, "%s", out_args[i]);
	}

	/* and install the new set of AV pairs as output */
	data->output_args = out_args;
	data->num_out_args = out_cnt;
	data->msg = tac_strdup(error_str);
	data->status = AUTHOR_STATUS_FAIL;
	return(1); /* no more processing required */
    }
}

/* If an after-authorization program has been specified, call it. It
 * can rewrite the output arguments in the authorization data, or
 * change the authorization status by calling an external program.
 */
static void
post_authorization(char *username, struct author_data *data)
{
    char **out_args;
    int out_cnt, i;
    int status;
    char *after = cfg_get_pvalue(username, TAC_IS_USER,
				S_after, TAC_PLUS_RECURSE);
    if (!after)
	return;

    if (debug & DEBUG_AUTHOR_FLAG)
	report(LOG_DEBUG, "After authorization call: %s", after);

    status = call_post_process(after, data, &out_args, &out_cnt);

    if (status != 2) {
	/* throw away out_args */
	for (i = 0; i < out_cnt; i++) {
	    free(out_args[i]);
	}
	free(out_args);
    }

    switch (status) {
    default:
	if (debug & DEBUG_AUTHOR_FLAG)
	    report(LOG_DEBUG,
		   "cmd %s returns %d (Error)", after, status);

	data->status = AUTHOR_STATUS_ERROR;
	return;

    case 0:				/* Permit */
	if (debug & DEBUG_AUTHOR_FLAG)
	    report(LOG_DEBUG, "cmd %s returns 0 (no change)", after);
	return;

    case 1:				/* Deny */
	if (debug & DEBUG_AUTHOR_FLAG)
	    report(LOG_DEBUG, "cmd %s returns %d (unconditional deny)",
		   after, status);

	data->status = AUTHOR_STATUS_FAIL;
	return;

    case 2:
	/* Use replacement AV pairs from program */
	if (debug & DEBUG_AUTHOR_FLAG)
	    report(LOG_DEBUG, "cmd %s returns 2 (replace & continue)",
		   after);

	/* Free any existing AV output pairs */
	if (data->num_out_args) {
	    for (i = 0; i < data->num_out_args; i++) {
		free(data->output_args[i]);
	    }
	    free(data->output_args);
	    data->output_args = NULL;
	}

	if (debug & DEBUG_AUTHOR_FLAG) {
	    report(LOG_DEBUG, "status is now AUTHOR_STATUS_PASS_REPL");
	}

	data->status = AUTHOR_STATUS_PASS_REPL;
	data->output_args = out_args;
	data->num_out_args = out_cnt;
	return;
    }
}

/* Return a pointer to the value part of an attr=value string */
static char *
value(char *s)
{
    while (*s != '\0' && *s != '=' && *s != '*')
	s++;
    if (*s != '\0')
	return(++s);
    return(NULL);
}

/*
 * Reassemble the command arguments as typed by the user, out of the
 * array of args we received. Return "" if there are no arguments.
 */
static char *
assemble_args(struct author_data *data)
{
    char *buf;
    int i;
    char *nas_arg, *v;
    int len;

    len = 0;
    for (i = 0; i < data->num_in_args; i++) {
	nas_arg = data->input_args[i];
	if (strncmp(nas_arg, "cmd-arg", strlen("cmd-arg")) == 0) {
	    v = value(nas_arg);
	    if (v != NULL)
		len += strlen(v) + 1;
	}
    }

    if (len <= 0) {
	return(tac_strdup(""));
    }

    buf = tac_malloc(len);
    buf[0] = '\0';

    for (i = 0; i < data->num_in_args; i++) {
	nas_arg = data->input_args[i];
	if (strncmp(nas_arg, "cmd-arg", strlen("cmd-arg")))
	    continue;

	v = value(nas_arg);
	if (!v) {
	    free(buf);
	    return(NULL);
	}
	strncat(buf, v, len - 1);
	len -= strlen(v);
	if (i < (data->num_in_args - 1)) {
	    strncat(buf, " ", len - 1);
	    len -= 1;
	}
    }
    return(buf);
}

/* See if an exec is authorized. Either the user has explicitly
 * authorized the exec, or she has authorized some commands (which
 * implicitly authorizes an exec), or the default is permit.
 *
 * If she has explicitly authorized an exec, we need to process its
 * attribute=value pairs. We indicate this by returning zero to the
 * caller.
 *
 * Otherwise, we return 1, indicating no further processing is
 * required for this request.
 */
static int
authorize_exec(char *user, struct author_data *data)
{
    NODE *svc;

    if (debug & DEBUG_AUTHOR_FLAG)
	report(LOG_DEBUG, "exec authorization request for %s", user);

    /*
     * Is an exec explicitly configured? If so, return 0 so we know to process
     * its attributes
     */
    svc = cfg_get_svc_node(user, N_svc_exec, NULL, NULL, TAC_PLUS_RECURSE);
    if (svc) {
	if (debug & DEBUG_AUTHOR_FLAG)
	    report(LOG_DEBUG, "exec is explicitly permitted by line %d",
		   svc->line);
	return(0);
    }

    /* No exec is configured. Are any commands configured? */
    svc = cfg_get_svc_node(user, N_svc_cmd, NULL, NULL, TAC_PLUS_RECURSE);
    if (svc) {
	if (debug & DEBUG_AUTHOR_FLAG)
	    report(LOG_DEBUG, "exec permitted because commands are configured");

	data->status = AUTHOR_STATUS_PASS_ADD;
	data->output_args = NULL;
	data->num_out_args = 0;
	return(1);
    }

    /* No exec or commands configured. What's the default? */
    if (cfg_user_svc_default_is_permit(user)) {

	if (debug & DEBUG_AUTHOR_FLAG)
	    report(LOG_DEBUG, "exec permitted by default");

	data->status = AUTHOR_STATUS_PASS_ADD;
	data->output_args = NULL;
	data->num_out_args = 0;
	return(1);
    }

    if (debug & DEBUG_AUTHOR_FLAG)
	report(LOG_DEBUG, "exec denied by default");

    data->status = AUTHOR_STATUS_FAIL;
    data->num_out_args = 0;
    return(1);
}

/*
 * Is an exec command authorized per our database(s)?  Return 0 if status is
 * valid.
 */
static int
authorize_cmd(char *user, char *cmd, struct author_data *data)
{
    char buf[256];
    NODE *node;
    char *args;
    int match;

    args = assemble_args(data);

    if (!cmd) {
	data->status = AUTHOR_STATUS_ERROR;
	data->admin_msg = tac_strdup("No command found");
	report(LOG_ERR, "%s: %s %s", session.peer, cmd, data->admin_msg);
	data->num_out_args = 0;
	return(0);
    }

    if (debug & DEBUG_AUTHOR_FLAG)
	report(LOG_DEBUG, "authorize_cmd: user=%s, cmd=%s", user, cmd);

    node = cfg_get_cmd_node(user, cmd, TAC_PLUS_RECURSE);

    /* The command does not exist. Do the default */
    if (!node) {
	if (cfg_user_svc_default_is_permit(user)) {
	    if (debug & DEBUG_AUTHOR_FLAG)
		report(LOG_DEBUG, "cmd %s does not exist, permitted by default",
		       cmd);
	    data->status = AUTHOR_STATUS_PASS_ADD;
	    data->num_out_args = 0;
	    if (args)
		free(args);
	    return(0);
	}

	if (debug & DEBUG_AUTHOR_FLAG)
	    report(LOG_DEBUG, "cmd %s does not exist, denied by default",
		   cmd);

	data->status = AUTHOR_STATUS_FAIL;
	data->num_out_args = 0;
	if (args)
	    free(args);
	return(0);
    }

    /* The command exists. The default if nothing matches is DENY */
    data->status = AUTHOR_STATUS_FAIL;
    data->num_out_args = 0;
    for (node = node->value1; node && args; node = node->next) {
	match = regexec((regex_t *)node->value1, args, 0, NULL, 0);

	if (debug & DEBUG_AUTHOR_FLAG) {
	    report(LOG_INFO, "line %d compare %s %s '%s' & '%s' %s",
		   node->line, cmd,
		   node->type == N_permit ? "permit" : "deny",
		   node->value, args,
		   (match == REG_NOMATCH ? "no match" :
			     !match ? "match" : "regex failure"));
	}

	if (match == REG_NOMATCH)
	    continue;
	if (match != REG_OK) {
	    regerror(match, (regex_t *)node->value1, buf, 256);
	    report(LOG_INFO, "regexec error: %s on line %d: %s",
		   (char *)node->value, node->line, buf);
	    continue;
	}

	switch (node->type) {
	case N_permit:
	    if (debug & DEBUG_AUTHOR_FLAG) {
		report(LOG_DEBUG, "%s %s permitted by line %d",
		       cmd, args, node->line);
	    }
	    data->status = AUTHOR_STATUS_PASS_ADD;
	    data->num_out_args = 0;
	    break;
	case N_deny:
	    if (debug & DEBUG_AUTHOR_FLAG) {
		report(LOG_DEBUG, "%s %s denied by line %d",
		       cmd, args, node->line);
	    }
	    data->status = AUTHOR_STATUS_FAIL;
	    data->num_out_args = 0;
	    break;
	default:
	    data->status = AUTHOR_STATUS_ERROR;
	    data->admin_msg = tac_strdup("Server error illegal configuration "
					 "node");
	    report(LOG_ERR, "%s: %s %s %s",
		   session.peer, cmd, args, data->admin_msg);
	    break;
	}
	if (args)
	    free(args);
	args = NULL;
	return(0);
    }
    if (args)
	free(args);
    return(0);
}

static int
is_separator(char ch)
{
    return(ch == '=' || ch == '*');
}

/* check an attr=value pair for well-formedness */
static int
arg_ok(char *arg)
{
    char *p = arg;

    /* It must contain an attribute */
    if (!*p)
	return(0);

    for (p = arg; *p; p++) {
	if (is_separator(*p)) {
	    if (p == arg) /* no attribute */
		return(0);
	    return(1);
	}
    }
    /* no separator */
    return(0);
}

/* return 1 if attrs match, 0 otherwise */
static int
match_attrs(char *nas_arg, char *server_arg)
{
    while (*nas_arg && *server_arg) {
	if (is_separator(*nas_arg) && is_separator(*server_arg)) {
	    return(1);
	}
	if (*nas_arg != *server_arg)
	    return(0);
	nas_arg++;
	server_arg++;
    }
    return(0);
}

/* return 1 if values match, 0 otherwise */
static int
match_values(char *nas_arg, char *server_arg)
{
    while (*nas_arg &&
	   *server_arg &&
	   !is_separator(*nas_arg)) {
	nas_arg++;
	server_arg++;
    }

    if (!*nas_arg)
	return(0);

    /* skip separator */
    nas_arg++;
    if (*server_arg)
	server_arg++;

    /* compare values */
    return(STREQ(nas_arg, server_arg));
}

/* Return 1 if arg is mandatory, 0 otherwise */
static int
mandatory(char *arg)
{
    char *p = arg;

    while (*p && !is_separator(*p))
	p++;

    /* if we're not at the end, this must be the separator */
    if (*p && !is_separator(*p)) {
	report(LOG_ERR, "%s: Error on arg %s cannot find separator",
	       session.peer, arg);
	return(0);
    }
    return(*p == '=');
}

static int
optional(char *arg)
{
    return(!mandatory(arg));
}

/*
 * PPP-LCP requests are a special case. If they are not explicitly configured,
 * but there are other ppp services explicitly configured, we admit (return 0)
 * any PPP-LCP request.
 */
static int
ppp_lcp_allowed(int svc, char *protocol, char *user)
{
    /* This is not a ppp/lcp request. Just Say No */
    if (!(svc == N_svc_ppp &&
	  protocol &&
	  STREQ(protocol, "lcp")))
	return(0);

    /* It is an LCP request. Are there PPP services configured */
    if (cfg_ppp_is_configured(user, TAC_PLUS_RECURSE)) {
	if (debug & DEBUG_AUTHOR_FLAG) {
	    report(LOG_DEBUG,
		   "ppp/lcp request permitted (ppp is configured for %s)",
		   user);
	}
	return(1);
    }

    /* It is an LCP request but no PPP services are configured */
    if (debug & DEBUG_AUTHOR_FLAG) {
	report(LOG_DEBUG, "ppp/lcp request denied (ppp not configured for %s)",
	       user);
    }
    return(0);
}

/*
 * Return 0 means data->status is valid.
 * protocol is only valid if svc == ppp.
 */
static int
authorize_svc(char *user, int svc, char *protocol, char *svcname,
	      struct author_data *data)
{
    int max_args;
    char **out_args, **outp;
    char *nas_arg, *cfg_arg;
    int i, j;
    char **cfg_args;
    char **cfg_argp;
    int deny_by_default;
    NODE *node;

    int replaced = 0;
    int added = 0;
    int cfg_cnt;

    /* Does this service exist? */
    node = cfg_get_svc_node(user, svc, protocol, svcname, TAC_PLUS_RECURSE);

    if (!node) {
	/* Service not found. If the default is permit, or this is an
	 * PPP/LCP request and other ppp services are configured,
	 * we'll allow it. */

	if (cfg_user_svc_default_is_permit(user)) {
	    if (debug & DEBUG_AUTHOR_FLAG)
		report(LOG_DEBUG, "svc=%s protocol=%s svcname=%s not found, "
		       "permitted by default", cfg_nodestring(svc),
		       protocol ? protocol : "", svcname ? svcname : "");

	    data->status = AUTHOR_STATUS_PASS_ADD;
	    data->num_out_args = 0;
	    data->output_args = NULL;
	    return(0);
	}

	if (ppp_lcp_allowed(svc, protocol, user)) {
	    data->status = AUTHOR_STATUS_PASS_ADD;
	    data->num_out_args = 0;
	    data->output_args = NULL;
	    return(0);
	}

	if (debug & DEBUG_AUTHOR_FLAG)
	    report(LOG_DEBUG, "svc=%s protocol=%s not found, denied by default",
		   cfg_nodestring(svc), protocol ? protocol : "");

	data->status = AUTHOR_STATUS_FAIL;
	data->num_out_args = 0;
	data->output_args = NULL;
	return(0);
    }

    /* Get server args configured in the config file. */
    cfg_args = cfg_get_svc_attrs(node, &deny_by_default);

    /* Check the nas args for well-formedness */
    for (i = 0; i < data->num_in_args; i++) {
	if (!arg_ok(data->input_args[i])) {
	    char buf[MAX_INPUT_LINE_LEN+50];
	    snprintf(buf, sizeof(buf), "Illegal arg %s from NAS",
		     data->input_args[i]);
	    data->status = AUTHOR_STATUS_ERROR;
	    data->admin_msg = tac_strdup(buf);
	    report(LOG_ERR, "%s: Error %s", session.peer, buf);

	    /* free any server arguments */
	    for (cfg_argp = cfg_args; cfg_args && *cfg_argp; cfg_argp++)
		free(*cfg_argp);
	    free(cfg_args);
	    return(0);
	}
    }

    /* How many configured AV pairs are there ? */
    for (cfg_cnt = 0; cfg_args && cfg_args[cfg_cnt];)
	cfg_cnt++;

    /* Allocate space for in + out args */
    max_args = cfg_cnt + data->num_in_args;
    out_args = (char **)tac_malloc((max_args + 1) * sizeof(char *));
    outp = out_args;
    data->num_out_args = 0;

    memset(out_args, 0, (max_args + 1) * sizeof(char *));

    for (i = 0; i < data->num_in_args; i++) {
	nas_arg = data->input_args[i];

	/* always pass these pairs through unchanged */
	if (match_attrs(nas_arg, "service=") ||
	    match_attrs(nas_arg, "protocol=") ||
	    match_attrs(nas_arg, "cmd=")) {

	    if (debug & DEBUG_AUTHOR_FLAG) {
		report(LOG_DEBUG, "nas:%s (passed thru)", nas_arg);
	    }
	    *outp++ = tac_strdup(nas_arg);
	    data->num_out_args++;
	    continue;
	}

	/* NAS AV pair is mandatory */
	if (mandatory(nas_arg)) {
	    /*
	     * a). look for an exact attribute,value match in the daemon's
	     * mandatory list. If found, add the AV pair to the output
	     */
	    for (j = 0; j < cfg_cnt; j++) {
		cfg_arg = cfg_args[j];
		if (optional(cfg_arg))
		    continue;

		if (STREQ(nas_arg, cfg_arg)) {
		    if (debug & DEBUG_AUTHOR_FLAG) {
			report(LOG_DEBUG, "nas:%s, svr:%s -> add %s (a)",
			       nas_arg, cfg_arg, nas_arg);
		    }
		    *outp++ = tac_strdup(nas_arg);
		    data->num_out_args++;
		    goto next_nas_arg;
		}
	    }

	    /*
	     * b). If an exact match doesn't exist, look in the daemon's
	     * optional list for the first attribute match. If found, add the
	     * NAS AV pair to the output
	     */
	    for (j = 0; j < cfg_cnt; j++) {
		cfg_arg = cfg_args[j];
		if (mandatory(cfg_arg))
		    continue;

		if (match_attrs(nas_arg, cfg_arg)) {
		    if (debug & DEBUG_AUTHOR_FLAG) {
			report(LOG_DEBUG, "nas:%s, svr:%s -> add %s (b)",
			       nas_arg, cfg_arg, nas_arg);
		    }
		    *outp++ = tac_strdup(nas_arg);
		    data->num_out_args++;
		    goto next_nas_arg;
		}
	    }

	    /*
	     * c). If no attribute match exists, deny the command if the
	     * default is to deny
	     */
	    if (deny_by_default) {
		data->status = AUTHOR_STATUS_FAIL;
		if (debug & DEBUG_AUTHOR_FLAG) {
		    report(LOG_DEBUG, "nas:%s svr:absent, default=deny -> "
							"denied (c)", nas_arg);
		}
		if (out_args) {
		    for (i = 0; i < data->num_out_args; i++)
			free(out_args[i]);
		    free(out_args);
		}

		data->num_out_args = 0;
		data->output_args = NULL;

		/* free the server arguments */
		for (cfg_argp = cfg_args; *cfg_argp; cfg_argp++)
		    free(*cfg_argp);
		free(cfg_args);
		return(0);
	    }

	    /*
	     * d). If the default is permit, add the NAS AV pair to the output
	     */
	    if (debug & DEBUG_AUTHOR_FLAG) {
		report(LOG_DEBUG,
		       "nas:%s, svr:absent, default=permit -> add %s (d)",
		       nas_arg, nas_arg);
	    }
	    *outp++ = tac_strdup(nas_arg);
	    data->num_out_args++;
	    goto next_nas_arg;
	} else {
	    /*
	     * NAS AV pair is Optional
	     *
	     * e). look for an exact attribute,value match in the mandatory
	     * list. If found, add DAEMON's AV pair to output
	     */
	    for (j = 0; j < cfg_cnt; j++) {
		cfg_arg = cfg_args[j];
		if (optional(cfg_arg))
		    continue;

		if (match_attrs(nas_arg, cfg_arg) &&
		    match_values(nas_arg, cfg_arg)) {

		    if (debug & DEBUG_AUTHOR_FLAG) {
			report(LOG_DEBUG, "nas:%s svr:%s -> replace with %s "
					"(e)", nas_arg, cfg_arg, cfg_arg);
		    }
		    *outp++ = tac_strdup(cfg_arg);
		    data->num_out_args++;
		    replaced++;
		    goto next_nas_arg;
		}
	    }

	    /*
	     * f). If not found, look for the first attribute match in the
	     * mandatory list. If found, add DAEMONS's AV pair to output
	     */
	    for (j = 0; j < cfg_cnt; j++) {
		cfg_arg = cfg_args[j];
		if (optional(cfg_arg))
		    continue;

		if (match_attrs(nas_arg, cfg_arg)) {
		    if (debug & DEBUG_AUTHOR_FLAG) {
			report(LOG_DEBUG, "nas:%s svr:%s -> replace with %s "
					"(f)", nas_arg, cfg_arg, cfg_arg);
		    }
		    *outp++ = tac_strdup(cfg_arg);
		    data->num_out_args++;
		    replaced++;
		    goto next_nas_arg;
		}
	    }

	    /*
	     * g). If no mandatory match exists, look for an exact
	     * attribute,value pair match among the daemon's optional AV
	     * pairs. If found add the DAEMON's matching AV pair to the
	     * output.
	     */
	    for (j = 0; j < cfg_cnt; j++) {
		cfg_arg = cfg_args[j];
		if (!optional(cfg_arg))
		    continue;

		if (match_attrs(nas_arg, cfg_arg) &&
		    match_values(nas_arg, cfg_arg)) {
		    if (debug & DEBUG_AUTHOR_FLAG) {
			report(LOG_DEBUG, "nas:%s svr:%s -> replace with %s "
					"(g)", nas_arg, cfg_arg, cfg_arg);
		    }
		    *outp++ = tac_strdup(cfg_arg);
		    data->num_out_args++;
		    replaced++;
		    goto next_nas_arg;
		}
	    }

	    /*
	     * h). If no exact match exists, locate the first attribute match
	     * among the daemon's optional AV pairs. If found add the DAEMON's
	     * matching AV pair to the output
	     */
	    for (j = 0; j < cfg_cnt; j++) {
		cfg_arg = cfg_args[j];
		if (!optional(cfg_arg))
		    continue;

		if (match_attrs(nas_arg, cfg_arg)) {
		    if (debug & DEBUG_AUTHOR_FLAG) {
			report(LOG_DEBUG, "nas:%s svr:%s -> replace with %s "
			       "(h)", nas_arg, cfg_arg, cfg_arg);
		    }
		    *outp++ = tac_strdup(cfg_arg);
		    data->num_out_args++;
		    replaced++;
		    goto next_nas_arg;
		}
	    }

	    /*
	     * i). If no match is found, delete the AV pair if default is deny
	     */
	    if (deny_by_default) {
		if (debug & DEBUG_AUTHOR_FLAG) {
		    report(LOG_DEBUG, "nas:%s svr:absent/deny -> delete %s (i)",
			   nas_arg, nas_arg);
		}
		replaced++;
		goto next_nas_arg;
	    }

	    /* j). If the default is permit add the NAS AV pair to the output */
	    if (debug & DEBUG_AUTHOR_FLAG) {
		report(LOG_DEBUG, "nas:%s svr:absent/permit -> add %s (j)",
		       nas_arg, nas_arg);
	    }
	    *outp++ = tac_strdup(nas_arg);
	    data->num_out_args++;
	    goto next_nas_arg;
	}
    next_nas_arg:;
    }

    /*
     * k). After all AV pairs have been processed, for each mandatory DAEMON
     * AV pair, if there is no attribute match already in the output list, add
     * the AV pair (add only one AV pair for each mandatory attribute)
     */
    for (i = 0; i < cfg_cnt; i++) {
	cfg_arg = cfg_args[i];

	if (!mandatory(cfg_arg))
	    continue;

	for (j = 0; j < data->num_out_args; j++) {
	    char *output_arg = out_args[j];

	    if (match_attrs(cfg_arg, output_arg)) {
		goto next_cfg_arg;
	    }
	}

	/* Attr is required by daemon but not present in output. Add it */
	if (debug & DEBUG_AUTHOR_FLAG) {
	    report(LOG_DEBUG, "nas:absent, server:%s -> add %s (k)",
		   cfg_arg, cfg_arg);
	}
	added++;
	*outp++ = tac_strdup(cfg_arg);
	data->num_out_args++;

    next_cfg_arg:
	;
    }

    /*
     * If we replaced or deleted some pairs we must return the entire list we
     * have constructed
     */
    if (replaced) {
	if (debug & DEBUG_AUTHOR_FLAG) {
	    report(LOG_DEBUG, "replaced %d args", replaced);
	}
	data->status = AUTHOR_STATUS_PASS_REPL;
	data->output_args = out_args;

	/* free the server arguments */
	for (cfg_argp = cfg_args; *cfg_argp; cfg_argp++)
	    free(*cfg_argp);
	free(cfg_args);

	return(0);
    }

    /*
     * We added something not on the original nas list, but did not replace or
     * delete anything. We should return only the additions
     */
    if (added) {
	if (debug & DEBUG_AUTHOR_FLAG)
	    report(LOG_DEBUG, "added %d args", added);

	/* throw away output args which are just copies of the input args */
	for (i = 0; i < data->num_in_args; i++) {
	    if (debug & DEBUG_AUTHOR_FLAG) {
		report(LOG_DEBUG, "out_args[%d] = %s input copy discarded",
		       i, out_args[i]);
	    }
	    free(out_args[i]);
	    out_args[i] = NULL;
	}

	/*
	 * Now compact the new args added to the end of the array down to the
	 * beginning
	 */
	j = 0;
	for (i = data->num_in_args; i < data->num_out_args; i++) {
	    if (out_args[j]) /* we goofed */
		report(LOG_ERR, "%s: out_args[%d] should be NULL",
		       session.peer, j);
	    if (!out_args[i]) /* we goofed */
		report(LOG_ERR, "%s: out_args[%d] should not be NULL",
		       session.peer, i);

	    if (debug & DEBUG_AUTHOR_FLAG) {
		report(LOG_DEBUG, "out_args[%d] = %s compacted to out_args[%d]",
		       i, out_args[i], j);
	    }
	    out_args[j++] = out_args[i];
	    out_args[i] = NULL;
	}
	data->num_out_args = j;
	if (debug & DEBUG_AUTHOR_FLAG) {
	    report(LOG_DEBUG, "%d output args", data->num_out_args);
	}

	/* should/could do a realloc here but it won't matter */
	data->status = AUTHOR_STATUS_PASS_ADD;
	data->output_args = out_args;

	/* free the server arguments */
	for (cfg_argp = cfg_args; *cfg_argp; cfg_argp++)
	    free(*cfg_argp);
	free(cfg_args);

	return(0);
    }

    /*
     * no additions or replacements. Input and output are identical. Don't
     * need to return anything
     */
    if (debug & DEBUG_AUTHOR_FLAG) {
	report(LOG_DEBUG, "added %d", added);
    }
    data->status = AUTHOR_STATUS_PASS_ADD;
    if (out_args) {
	for (i = 0; i < data->num_out_args; i++) {
	    free(out_args[i]);
	}
	free(out_args);
    }

    /* Final sanity check */
    if (data->num_out_args != data->num_in_args) {
	data->status = AUTHOR_STATUS_ERROR;
	data->admin_msg = tac_strdup("Bad output arg cnt from do_author");
	report(LOG_ERR, "%s: Error %s", session.peer, data->admin_msg);

	/* free the server arguments */
	for (cfg_argp = cfg_args; *cfg_argp; cfg_argp++)
	    free(*cfg_argp);
	free(cfg_args);

	return(0);
    }

    data->num_out_args = 0;
    data->output_args = NULL;

    /* free the server arguments */
    for (cfg_argp = cfg_args; *cfg_argp; cfg_argp++)
	free(*cfg_argp);
    free(cfg_args);

    return(0);
}

/*
 * Return an integer indicating which kind of service is being requested.
 *
 * Conveniently this integer is one of our node types.  If the service
 * is a command authorisation request, also return the command name in
 * cmdname.
 *
 * If this service is a ppp request, return the protocol name in protocol.
 *
 * If this service is not one of the standard, known ones, return its
 * name in svcname.
 */
static int
get_nas_svc(struct author_data *data, char **cmdname, char **protocol,
	    char **svcname)
{
    int i;
    char *nas_arg;

    *cmdname = NULL;
    *protocol = NULL;
    *svcname = NULL;

    for (i = 0; i < data->num_in_args; i++) {
	nas_arg = data->input_args[i];

	if (STREQ(nas_arg, "service=shell")) {
	    for (i = 0; i < data->num_in_args; i++) {
		nas_arg = data->input_args[i];
		if (strncmp(nas_arg, "cmd", strlen("cmd")) == 0) {
		    /* A cmd=<nothing> means we are authorising exec startup */
		    if ((int)strlen(nas_arg) <= 4)
			return(N_svc_exec);

		    /* A non-null command means we are authorising a command */
		    *cmdname = nas_arg + strlen("cmd") + 1;
		    return(N_svc_cmd);
		}
	    }
	    return(0);
	}

	if (STREQ(nas_arg, "service=slip")) {
	    return(N_svc_slip);
	}
	if (STREQ(nas_arg, "service=arap")) {
	    return(N_svc_arap);
	}
	if (STREQ(nas_arg, "service=ppp")) {
	    for (i = 0; i < data->num_in_args; i++) {
		nas_arg = data->input_args[i];
		if (strncmp(nas_arg, "protocol", strlen("protocol")) == 0) {
		    *protocol = nas_arg + strlen("protocol") + 1;
		    return(N_svc_ppp);
		}
	    }
	}

	if (strncmp(nas_arg, "service=", strlen("service=")) ==0 ) {
	    *svcname = nas_arg + strlen("service=");
	    return(N_svc);
	}
    }
    return(0);
}
