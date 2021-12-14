/*
 * $Id: config.c,v 1.48 2009-04-10 16:19:04 heas Exp $
 *
 * Copyright (c) Facebook, Inc. and its affiliates. All Rights Reserved
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

/*
   <config>		:=	<decl>*

   <decl>		:=	<top_level_decl> |
				<acl_decl> |
				<user_decl> |
				<group_decl> |
				<host_decl>

   <top_level_decl>	:=	<authen_default> |
				accounting file = <filename> |
				accounting syslog |
				key = <string> |
				logging = <syslog_fac> |
        maxprocs = <maxprocs> |
        maxprocsperclt = <maxprocsperclt>

   <authen_default>	:=	default authentication = file <filename>

   <permission>		:=	permit | deny

   <filename>		:=	<string>

   <password>		:=	<string>

   <syslog_fac>		:=	(auth|cron|daemon|ftp|kern|lpr|mail|news|
				 syslog|user|uucp|local[0-7])

  <logauthor>

   <host_decl>		:=	host = <string> {
					key = <string>
					prompt = <string>
					enable = aceclnt|cleartext|des|
						 file <filename/string>|
						 nopassword|skey
				}

   <user_decl>		:=	user = <string> {
					[ default service = <permission> ]
					<user_attr>*
					<svc>*
				}

   <password_spec>	:=	nopassword |
#ifdef ACECLNT
				aceclnt|
#endif
				cleartext <password> |
				des <password> |
				file <filename> |
#ifdef HAVE_PAM
				PAM |
#endif
				skey

   <user_attr>		:=	name	= <string> |
				login	= <password_spec> |
				member	= <string> |
				expires	= <string> |
				arap	= cleartext <string> |
				chap	= cleartext <string> |
#ifdef MSCHAP
				ms-chap	= cleartext <string> |
#endif
				pap	= cleartext <string> |
				pap	= des <string> |
#ifdef HAVE_PAM
				pap	= PAM |
#endif
				opap	= cleartext <string> |
				global	= cleartext <string> |
				msg	= <string>
				before authorization = <string> |
				after authorization = <string>

   <svc>		:=	<svc_auth> | <cmd_auth>

   <cmd_auth>		:=	cmd = <string> {
					<cmd-match>*
				}

   <cmd-match>		:=	<permission> <string>

   <proto>		:=	XXX define this

   <svc_auth>		:=	service = ( arap | connection | exec |
					    ppp protocol = <proto> | shell |
					    slip | system | tty-daemon |
					    <client defined> ) {
					[ default attribute = permit ]
					<attr_value_pair>*
				}

   <attr_value_pair>	:=	[ optional ] <string> = <string>

*/

static char sym_buf[MAX_INPUT_LINE_LEN];	/* parse buffer */
static int sym_pos = 0;				/* current place in sym_buf */
static int sym_ch;				/* current parse character */
static int sym_code;				/* parser output */
static int sym_line = 1;			/* current line number */
static FILE *cf = NULL;				/* config file pointer */
static int sym_error = 0;			/* a parsing error occurred */
static char *authen_default = NULL;	/* top level authentication default */
static char *nopasswd_str = "nopassword";
static long int maxprocs = TAC_MAX_PROCS; /* max procs to fork */
static long int maxprocsperclt = TAC_MAX_PROCS_PER_CLIENT; /* max per client */
static long int readtimeout = TAC_PLUS_READ_TIMEOUT; /* read timeout */
static long int writetimeout = TAC_PLUS_WRITE_TIMEOUT; /* write timeout */
static long int accepttimeout = TAC_PLUS_ACCEPT_TIMEOUT; /* accept timeout */
static int logauthor = 0; /* log authorization requests */

/*
 * A host definition structure.
 * host-specific information e.g. per-host keys
 *
 * The first 2 fields (name and hash) are used by the hash table routines to
 * hash this structure into a table.  Do not (re)move them.
 */
typedef struct host {
    char *name;			/* host name */
    void *hash;			/* hash table next pointer */
    int line;			/* line number defined on */
    char *key;			/* host specific key */
    /*char *type;*/		/* host type - XXX: no idea what should be
				 * here */
    char *prompt;		/* host login/username prompt string */
    char *enable;		/* host enable password */
    int noenablepwd;		/* host requires no enable password */
} HOST;

/*
 * A user or group definition
 * The first 2 fields (name and hash) are used by the hash table
 * routines to hash this structure into a table.  Move them at your peril
 */
typedef struct user {
    char *name;			/* username */
    void *hash;			/* hash table next pointer */
    int line;			/* line number defined on */
    long flags;			/* flags field */
#define FLAG_ISUSER  1		/* this structure represents a user */
#define FLAG_ISGROUP 2		/* this structure represents a group */
#define FLAG_SEEN    4		/* for circular definition detection */

    char *full_name;		/* users full name */
    char *login;		/* Login password */
    int nopasswd;		/* user requires no password */
#ifdef ACLS
    char *acl;			/* hosts (NASs) to allow / deny ACL */
# ifdef UENABLE
    char *enable;		/* user enable pwd */
    int noenablepwd;		/* user requires no enable password */
    char *enableacl;		/* hosts (NASs) to allow/deny enabling */
# endif
#endif
    char *global;		/* password to use if none set */
    char *member;		/* group we are a member of */
    char *expires;		/* expiration date */
    char *arap;			/* our arap secret */
    char *pap;			/* our pap secret */
    char *opap;			/* our outbound pap secret */
    char *chap;			/* our chap secret */
#ifdef MSCHAP
    char *mschap;		/* our mschap secret */
#endif /* MSCHAP */
    char *msg;			/* a message for this user */
    char *before_author;	/* command to run before authorization */
    char *after_author;		/* command to run after authorization */
    int svc_dflt;		/* default authorization behaviour for svc or
				 * cmd */
    NODE *svcs;			/* pointer to svc nodes */
#ifdef MAXSESS
    int maxsess;		/* Max sessions/user */
#endif /* MAXSESS */
} USER;
typedef USER GROUP;

#ifdef ACLS
typedef struct filter {
    int isdeny;
    char *string;
    regex_t *string_reg;
    struct filter *next;
} FILTER;

typedef struct acl {
    char *name;			/* acl name */
    void *hash;			/* hash table next pointer */
    int line;			/* line number defined on */
    NODE *nodes;		/* list of entrys */
} ACL;
#endif

/*
 * Only the first 2 fields (name and hash) are used by the hash table
 * routines to hash structures into a table.
 */
typedef union hash {
    struct user u;
#ifdef ACLS
    struct acl a;
#endif
    struct host h;
} HASH;

void *grouptable[HASH_TAB_SIZE];/* Table of group declarations */
void *usertable[HASH_TAB_SIZE];	/* Table of user declarations */
#ifdef ACLS
void *acltable[HASH_TAB_SIZE];	/* Table of ACL declarations */
#endif
void *hosttable[HASH_TAB_SIZE];	/* Table of host declarations */

static VALUE	cfg_get_hvalue(char *, int);
static VALUE	cfg_get_value(char *, int, int, int);
static int	circularity_check(void);
static void	free_aclstruct(ACL *);
static void	free_attrs(NODE *);
static void	free_cmd_matches(NODE *);
static void	free_hoststruct(HOST *);
static void	free_svcs(NODE *);
static void	free_userstruct(USER *);
static void	getsym(void);
static VALUE	get_value(USER *, int);
#ifdef ACLS
static int	insert_acl_entry(ACL *, int);
static int	parse_acl(void);
#endif
static NODE	*parse_attrs(void);
static NODE	*parse_cmd_matches(void);
static int	parse_logging(void);
static int	parse_host(void);
static int	parse_opt_attr_default(void);
static int	parse_opt_svc_default(void);
static int	parse_permission(void);
static NODE	*parse_svcs(void);
static int	parse_user(void);
static void	rch(void);
static void	sym_get(void);

#ifdef __STDC__
#include <stdarg.h>		/* ANSI C, variable length args */
static void
parse_error(char *fmt, ...)
#else
#include <varargs.h>		/* has 'vararg' definitions */
/* VARARGS2 */
static void
parse_error(fmt, va_alist)
    char *fmt;
    va_dcl				/* no terminating semi-colon */
#endif
{
    char msg[256];			/* temporary string */
    va_list ap;

#ifdef __STDC__
    va_start(ap, fmt);
#else
    va_start(ap);
#endif
    vsprintf(msg, fmt, ap);
    va_end(ap);

    report(LOG_ERR, "%s", msg);
    fprintf(stderr, "Error: %s\n", msg);
    tac_exit(1);
}

char *
cfg_nodestring(int type)
{
    switch (type) {
    default:
	return("unknown node type");
    case N_arg:
	return("N_arg");
    case N_optarg:
	return("N_optarg");
    case N_svc:
	return("N_svc");
    case N_svc_exec:
	return("N_svc_exec");
    case N_svc_slip:
	return("N_svc_slip");
    case N_svc_ppp:
	return("N_svc_ppp");
    case N_svc_arap:
	return("N_svc_arap");
    case N_svc_cmd:
	return("N_svc_cmd");
    case N_permit:
	return("N_permit");
    case N_deny:
	return("N_deny");
    }
}

static void
free_attrs(NODE *node)
{
    NODE *next;

    while (node) {
	switch (node->type) {
	case N_optarg:
	case N_arg:
	    if (debug & DEBUG_CLEAN_FLAG)
		report(LOG_DEBUG, "free_cmd_match %s %s",
		       cfg_nodestring(node->type), node->value);
	    break;
	default:
	    report(LOG_ERR, "Illegal node type %s for free_attrs",
		   cfg_nodestring(node->type));
	    return;
	}

	free(node->value);
	next = node->next;
	free(node);
	node = next;
    }
}

#ifdef ACLS
static void
free_aclstruct(ACL *acl)
{
    NODE *last, *next = acl->nodes;

    last = next;

    if (debug & DEBUG_CLEAN_FLAG)
	report(LOG_DEBUG, "free_aclstruct %s", acl->name);

    while (next) {
	if (debug & DEBUG_CLEAN_FLAG)
	    report(LOG_DEBUG, "free_aclstruct %s %s", acl->name, next->value);
	if (next->value)
	    free(next->value);
	if (next->value1)
	    free(next->value1);
	next = next->next;
	free(last);
	last = next;
    }

    if (acl->name)
	free(acl->name);
}
#endif

static void
free_cmd_matches(NODE *node)
{
    NODE *next;

    while (node) {
	if (debug & DEBUG_CLEAN_FLAG)
	    report(LOG_DEBUG, "free_cmd_match %s %s",
		   cfg_nodestring(node->type),
		   node->value);

	free(node->value);	/* text */
	free(node->value1);	/* regexp compiled text */
	next = node->next;
	free(node);
	node = next;
    }
}

static void
free_hoststruct(HOST *host)
{
    if (debug & DEBUG_CLEAN_FLAG)
	report(LOG_DEBUG, "free %s", host->name);

    if (host->name)
	free(host->name);
    if (host->key)
	free(host->key);
    /* if (host->type)
	free(host->type); */
    if (host->prompt)
	free(host->prompt);
    if (host->enable)
	free(host->enable);

    return;
}

static void
free_svcs(NODE *node)
{
    NODE *next;

    while (node) {

	switch (node->type) {
	case N_svc_cmd:
	    if (debug & DEBUG_CLEAN_FLAG)
		report(LOG_DEBUG, "free %s %s",
		       cfg_nodestring(node->type), node->value);
	    free(node->value);	/* cmd name */
	    free_cmd_matches(node->value1);
	    next = node->next;
	    free(node);
	    node = next;
	    continue;

	case N_svc:
	case N_svc_ppp:
	    free(node->value1);
	    /* FALL-THROUGH */
	case N_svc_exec:
	case N_svc_arap:
	case N_svc_slip:
	    if (debug & DEBUG_CLEAN_FLAG)
		report(LOG_DEBUG, "free %s", cfg_nodestring(node->type));
	    free_attrs(node->value);
	    next = node->next;
	    free(node);
	    node = next;
	    continue;

	default:
	    report(LOG_ERR, "Illegal node type %d for free_svcs", node->type);
	    return;
	}
    }
}

static void
free_userstruct(USER *user)
{
    if (debug & DEBUG_CLEAN_FLAG)
	report(LOG_DEBUG, "free %s %s",
	       (user->flags & FLAG_ISUSER) ? "user" : "group",
	       user->name);

    if (user->name)
	free(user->name);
    if (user->full_name)
	free(user->full_name);
    if (user->login)
	free(user->login);
    if (user->member)
	free(user->member);
#ifdef ACLS
    if (user->acl)
	free(user->acl);
# ifdef UENABLE
    if (user->enable)
	free(user->enable);
    if (user->enableacl)
	free(user->enableacl);
# endif
#endif
    if (user->expires)
	free(user->expires);
    if (user->arap)
	free(user->arap);
    if (user->chap)
	free(user->chap);
#ifdef MSCHAP
    if (user->mschap)
	free(user->mschap);
#endif /* MSCHAP */
    if (user->pap)
	free(user->pap);
    if (user->opap)
	free(user->opap);
    if (user->global)
	free(user->global);
    if (user->msg)
	free(user->msg);
    if (user->before_author)
	free(user->before_author);
    if (user->after_author)
	free(user->after_author);
    free_svcs(user->svcs);
}

/*
 * Exported routines
 */

/* Free all allocated structures preparatory to re-reading the config file */
void
cfg_clean_config(void)
{
    int i;
    USER *entry, *next;
    HOST *host_entry, *hn;
#ifdef ACLS
    ACL *aentry, *anext;
#endif

    if (authen_default) {
	free(authen_default);
	authen_default = NULL;
    }

    if (session.key) {
	free(session.key);
	session.key = NULL;
    }

    if (session.acctfile) {
	free(session.acctfile);
	session.acctfile = NULL;
    }
    session.flags = 0;

#ifdef ACLS
    /* clean the acltable */
    for (i = 0; i < HASH_TAB_SIZE; i++) {
	aentry = (ACL *)acltable[i];
	while (aentry) {
	    anext = aentry->hash;
	    free_aclstruct(aentry);
	    free(aentry);
	    aentry = anext;
	}
	acltable[i] = NULL;
    }
#endif

    /* the grouptable */
    for (i = 0; i < HASH_TAB_SIZE; i++) {
	entry = (USER *)grouptable[i];
	while (entry) {
	    next = entry->hash;
	    free_userstruct(entry);
	    free(entry);
	    entry = next;
	}
	grouptable[i] = NULL;
    }

    /* clean the hosttable */
    for (i = 0; i < HASH_TAB_SIZE; i++) {
	host_entry = (HOST *)hosttable[i];
	while (host_entry) {
	    hn = host_entry->hash;
	    free_hoststruct(host_entry);
	    free(host_entry);
	    host_entry = hn;
	}
	hosttable[i] = NULL;
    }

    /* the usertable */
    for (i = 0; i < HASH_TAB_SIZE; i++) {
	entry = (USER *)usertable[i];
	while (entry) {
	    next = entry->hash;
	    free_userstruct(entry);
	    free(entry);
	    entry = next;
	}
	usertable[i] = NULL;
    }
}

static int
parse_permission(void)
{
    int symbol = sym_code;

    if (sym_code != S_permit && sym_code != S_deny) {
	parse_error("expecting permit or deny but found '%s' on line %d",
		    sym_buf, sym_line);
	return(0);
    }
    sym_get();

    return(symbol);
}

static int
parse(int symbol)
{
    if (sym_code != symbol) {
	parse_error("expecting '%s' but found '%s' on line %d",
		    (symbol == S_string ? "string" : codestring(symbol)),
		    sym_buf, sym_line);
	return(1);
    }
    sym_get();
    return(0);
}

static int
parse_opt_svc_default(void)
{
    if (sym_code != S_default) {
	return(0);
    }

    parse(S_default);
    parse(S_svc);
    parse(S_separator);
    if (sym_code == S_permit) {
	parse(S_permit);
	return(S_permit);
    }
    parse(S_deny);
    return(S_deny);
}

static int
parse_opt_attr_default(void)
{
    if (sym_code != S_default)
	return(S_deny);

    parse(S_default);
    parse(S_attr);
    parse(S_separator);
    parse(S_permit);
    return(S_permit);
}

#ifdef ACLS
/* insert an acl entry into the named acl node list */
static int
insert_acl_entry(ACL *acl, int isdeny)
{
    char buf[256];
    NODE *next = acl->nodes;
    NODE *entry = (NODE *)tac_malloc(sizeof(NODE));
    int ecode;

    memset(entry, 0, sizeof(NODE));

    entry->type = isdeny;
    entry->value = tac_strdup(sym_buf);
    entry->line = sym_line;

    /* compile the regex */
    entry->value1 = tac_malloc(sizeof(regex_t));
    ecode = regcomp((regex_t *)entry->value1, (char *)entry->value,
		    (REG_EXTENDED | REG_NOSUB));
    if (ecode) {
	regerror(ecode, (regex_t *)entry->value1, buf, 256);
	report(LOG_ERR, "in regex %s on line %d", sym_buf, sym_line);
	report(LOG_ERR, "regex compile failed: %s", buf);
	tac_exit(1);
    }

    if (acl->nodes == NULL) {
	acl->nodes = entry;
	return(0);
    }

    while (next->next != NULL) {
	next = next->next;
    }
    next->next = entry;

    return(0);
}

/* parse the acl = NAME { allow = regex  deny = regex } */
static int
parse_acl(void)
{
    ACL *n;
    ACL *acl = (ACL *)tac_malloc(sizeof(ACL));
    int isdeny = S_permit;

    memset(acl, 0, sizeof(ACL));

    sym_get();
    parse(S_separator);
    acl->name = tac_strdup(sym_buf);
    acl->line = sym_line;

    n = hash_add_entry(acltable, (void *)acl);

    if (n) {
	parse_error("multiply defined acl %s on lines %d and %d", acl->name,
		    n->line, sym_line);
	return(1);
    }
    sym_get();
    parse(S_openbra);

    while (1) {
	switch (sym_code) {
	case S_eof:
	    return(0);

	case S_deny:
	    isdeny = S_deny;
	case S_permit:
	    sym_get();
	    parse(S_separator);
	    insert_acl_entry(acl, isdeny);
	    parse(S_string);
	    isdeny = S_permit;
	    continue;

	case S_closebra:
	    parse(S_closebra);
	    return(0);

	default:
	    parse_error("Unrecognised keyword %s for acl on line %d", sym_buf,
			sym_line);

	    return(0);
	}
    }
}
#endif

/*
 * Parse lines in the config file, creating data structures.
 * Return 1 on error, otherwise 0
 */
static int
parse_decls()
{

    sym_code = 0;
    rch();

#ifdef ACLS
    memset(acltable, 0, sizeof(acltable));
#endif
    memset(grouptable, 0, sizeof(grouptable));
    memset(usertable, 0, sizeof(usertable));
    memset(hosttable, 0, sizeof(hosttable));

    sym_get();

    /* Top level of parser */
    while (1) {

	switch (sym_code) {
	case S_eof:
	    return(0);

	case S_accounting:
	    sym_get();

	    switch(sym_code) {
		case S_file:
		    parse(S_file);
		    parse(S_separator);
		    if (session.acctfile != NULL)
			free(session.acctfile);
		    session.acctfile = tac_strdup(sym_buf);
		    break;

		case S_syslog:
		    session.flags |= SESS_FLAG_ACCTSYSL;
		    break;
	    }

	    sym_get();
	    continue;

	case S_default:
	    sym_get();
	    switch (sym_code) {
	    default:
		parse_error("Expecting default authentication on line %d",
			    sym_line);
		return(1);

	    case S_authentication:
		if (authen_default) {
		    parse_error("Multiply defined authentication default on "
				"line %d", sym_line);
		    return(1);
		}
		parse(S_authentication);
		parse(S_separator);
		parse(S_file);
		authen_default = tac_strdup(sym_buf);
		sym_get();
		continue;
	    }

	case S_key:
	    /* Process a key declaration. */
	    sym_get();
	    parse(S_separator);
	    if (session.key) {
		parse_error("multiply defined key on lines %d and %d",
			    session.keyline, sym_line);
		return(1);
	    }
	    session.key = tac_strdup(sym_buf);
	    session.keyline = sym_line;
	    sym_get();
	    continue;

  case S_maxprocs:
        parse(S_maxprocs);
  		  parse(S_separator);
        errno = 0;
        maxprocs = strtol(tac_strdup(sym_buf), NULL, 10);
        if ((errno) || (maxprocs < 0)) {
          parse_error("maxprocs must a valid positive integer");
          return 1;
        }
        sym_get();
        continue;

    case S_maxprocsperclt:
        parse(S_maxprocsperclt);
        parse(S_separator);
        errno = 0;
        maxprocsperclt = strtol(tac_strdup(sym_buf), NULL, 10);
        if ((errno) || (maxprocsperclt < 0)) {
          parse_error("maxprocsperclt must a valid positive integer");
          return 1;
        }
        sym_get();
        continue;

    case S_readtimeout:
        parse(S_readtimeout);
        parse(S_separator);
        errno = 0;
        readtimeout = strtol(tac_strdup(sym_buf), NULL, 10);
        if ((errno) || (readtimeout < 0)) {
          parse_error("readtimeout must a valid positive integer");
          return 1;
        }
        sym_get();
        continue;

    case S_writetimeout:
        parse(S_writetimeout);
        parse(S_separator);
        errno = 0;
        writetimeout = strtol(tac_strdup(sym_buf), NULL, 10);
        if ((errno) || (writetimeout < 0)) {
          parse_error("writetimeout must a valid positive integer");
          return 1;
        }
        sym_get();
        continue;

    case S_accepttimeout:
        parse(S_accepttimeout);
        parse(S_separator);
        errno = 0;
        accepttimeout = strtol(tac_strdup(sym_buf), NULL, 10);
        if ((errno) || (accepttimeout < 0)) {
          parse_error("accepttimeout must a valid positive integer");
          return 1;
        }
        sym_get();
        continue;

  case S_logauthor:
      parse(S_logauthor);
      logauthor = 1;
      continue;

	case S_host:
	    parse_host();
	    continue;

	case S_user:
	case S_group:
	    parse_user();
	    continue;

#ifdef ACLS
	case S_acl:
	    parse_acl();
	    continue;
#endif

	case S_logging:
	    parse_logging();
	    continue;

	default:
	    parse_error("Unrecognised token %s on line %d", sym_buf, sym_line);
	    return(1);
	}
    }
}

/*
 * Assign a value to a field.  Issue an error message and return 1 if
 * it has already been assigned.  This is a macro because I was sick of
 * repeating the same code fragment over and over.
 */
#define ASSIGN(field) \
sym_get(); parse(S_separator); if (field) { \
	parse_error("Duplicate value for %s %s and %s on line %d", \
		    codestring(sym_code), field, sym_buf, sym_line); \
	tac_exit(1); \
    } \
    field = tac_strdup(sym_buf);

static int
parse_host(void)
{
    HOST *h;
    HOST *host = (HOST *)tac_malloc(sizeof(HOST));
    char buf[MAX_INPUT_LINE_LEN];

    memset(host, 0, sizeof(HOST));

    sym_get();
    parse(S_separator);
    host->name = tac_strdup(sym_buf);
    host->line = sym_line;

    h = hash_add_entry(hosttable, (void *)host);

    if (h) {
	parse_error("multiply defined %s on lines %d and %d", host->name,
		    h->line, sym_line);
	return(1);
    }

    sym_get();
    parse(S_openbra);

    while (1) {
	switch (sym_code) {
	case S_eof:
	    return(0);
	case S_key:
	    ASSIGN(host->key);
	    sym_get();
	    continue;

	case S_prompt:
	    ASSIGN(host->prompt);
	    sym_get();
	    continue;

	case S_enable:
	    if (host->enable) {
		parse_error("Duplicate value for %s %s and %s on line %d",
			    codestring(sym_code), host->enable, sym_buf,
			    sym_line);
		tac_exit(1);
	    }
	    sym_get();
	    parse(S_separator);
	    switch(sym_code) {

	    case S_cleartext:
	    case S_des:
		sprintf(buf, "%s ", sym_buf);
		sym_get();
		/* XXX: naughty, this should check the size */
		strcat(buf, sym_buf);
		host->enable = tac_strdup(buf);
		break;

	    case S_nopasswd:
		/* set to dummy string, so that we detect a duplicate
		 * password definition attempt
		 */
		host->enable = tac_strdup(nopasswd_str);
		host->noenablepwd = 1;
		break;

	    default:
		parse_error("expecting 'cleartext' or 'des' keyword after "
			    "'enable =' on line %d", sym_line);
	    }
	    sym_get();
	    continue;

	case S_closebra:
	    parse(S_closebra);
	    return(0);

	default:
	    parse_error("Unrecognised keyword %s for host %s on line %d",
			sym_buf, host->name,sym_line);

	    return(0);
	}
    }
}

/*
 * Parse logging statement.
 * Return 1 on error, otherwise 0
 */
static int
parse_logging(void)
{
    struct _facs	{ char *name;
			  int level;
			} facs[] = {	{"auth", LOG_AUTH},
					{"cron", LOG_CRON},
					{"daemon", LOG_DAEMON},
#ifdef LOG_FTP
					{"ftp", LOG_FTP},
#endif
					{"kern", LOG_KERN},
					{"local0", LOG_LOCAL0},
					{"local1", LOG_LOCAL1},
					{"local2", LOG_LOCAL2},
					{"local3", LOG_LOCAL3},
					{"local4", LOG_LOCAL4},
					{"local5", LOG_LOCAL5},
					{"local6", LOG_LOCAL6},
					{"local7", LOG_LOCAL7},
					{"lpr", LOG_LPR},
					{"mail", LOG_MAIL},
					{"news", LOG_NEWS},
					{"syslog", LOG_SYSLOG},
					{"user", LOG_USER},
					{"uucp", LOG_UUCP},
					{NULL, 0}
				   };
    int	fac;

    sym_get();
    parse(S_separator);

    for (fac = 0; sym_code == S_string && facs[fac].name != NULL; fac++) {
	if (strcmp(sym_buf, facs[fac].name) == 0)
	    break;
    }
    if (facs[fac].name == NULL)
	parse_error("expecting syslog facility on line %d, got %s", sym_line,
		    sym_buf);

    facility = facs[fac].level;
    closelog();
    open_logfile();

    sym_get();
    return(0);
}

static int
parse_user(void)
{
    USER *n;
    int isuser;
    USER *user = (USER *)tac_malloc(sizeof(USER));
    int save_sym;
    char **fieldp;
    char buf[MAX_INPUT_LINE_LEN];

    fieldp = NULL;
    memset(user, 0, sizeof(USER));

    isuser = (sym_code == S_user);

    sym_get();
    parse(S_separator);
    user->name = tac_strdup(sym_buf);
    user->line = sym_line;

    if (isuser) {
	user->flags |= FLAG_ISUSER;
	n = hash_add_entry(usertable, (void *)user);
    } else {
	user->flags |= FLAG_ISGROUP;
	n = hash_add_entry(grouptable, (void *)user);
    }

    if (n) {
	parse_error("multiply defined %s %s on lines %d and %d",
		    isuser ? "user" : "group",
		    user->name, n->line, sym_line);
	return(1);
    }
    sym_get();
    parse(S_openbra);

    /* Is the default deny for svcs or cmds to be overridden? */
    user->svc_dflt = parse_opt_svc_default();

    while (1) {
	switch (sym_code) {
	case S_eof:
	    return(0);

	case S_before:
	    sym_get();
	    parse(S_authorization);
	    if (user->before_author)
		free(user->before_author);
	    user->before_author = tac_strdup(sym_buf);
	    sym_get();
	    continue;

	case S_after:
	    sym_get();
	    parse(S_authorization);
	    if (user->after_author)
		free(user->after_author);
	    user->after_author = tac_strdup(sym_buf);
	    sym_get();
	    continue;

	case S_svc:
	case S_cmd:
	    if (user->svcs) {
		/*
		 * Already parsed some services/commands. Thanks to Gabor Kiss
		 * who found this bug.
		 */
		NODE *p;
		for (p = user->svcs; p->next; p = p->next)
		    /* NULL STMT */;
		p->next = parse_svcs();
	    } else {
		user->svcs = parse_svcs();
	    }
	    continue;

	case S_login:
	    if (user->login) {
		parse_error("Duplicate value for %s %s and %s on line %d",
			    codestring(sym_code), user->login,
			    sym_buf, sym_line);
		tac_exit(1);
	    }
	    sym_get();
	    parse(S_separator);
	    switch(sym_code) {

#ifdef SKEY
	    case S_skey:
		user->login = tac_strdup(sym_buf);
		break;
#endif

#ifdef ACECLNT
	    case S_aceclnt:
		user->login = tac_strdup(sym_buf);
		break;
#endif

#ifdef HAVE_PAM
	    case S_pam:
		user->login = tac_strdup(sym_buf);
		break;
#endif

	    case S_nopasswd:
		/*
		 * set to dummy string, so that we detect a duplicate
		 * password definition attempt
		 */
		user->login = tac_strdup(nopasswd_str);
		user->nopasswd = 1;
		break;

	    case S_file:
	    case S_cleartext:
	    case S_des:
		sprintf(buf, "%s ", sym_buf);
		sym_get();
		strcat(buf, sym_buf);
		user->login = tac_strdup(buf);
		break;

	    default:
		parse_error("expecting 'file', 'cleartext', 'nopassword', "
#ifdef SKEY
			    "'skey', "
#endif
#ifdef ACECLNT
			    "'aceclnt', "
#endif
#ifdef HAVE_PAM
			    "'PAM', "
#endif
			    "or 'des' keyword after 'login =' on line %d",
			    sym_line);
	    }
	    sym_get();
	    continue;

	case S_pap:
	    if (user->pap) {
		parse_error("Duplicate value for %s %s and %s on line %d",
			    codestring(sym_code), user->pap,
			    sym_buf, sym_line);
		tac_exit(1);
	    }
	    sym_get();
	    parse(S_separator);
	    switch(sym_code) {

#ifdef HAVE_PAM
	    case S_pam:
		user->pap = tac_strdup(sym_buf);
		break;
#endif

	    case S_file:
	    case S_cleartext:
	    case S_des:
		sprintf(buf, "%s ", sym_buf);
		sym_get();
		strcat(buf, sym_buf);
		user->pap = tac_strdup(buf);
		break;

	    default:
		parse_error("expecting 'cleartext', "
#ifdef HAVE_PAM
			    "'PAM', "
#endif
			    "or 'des' keyword after "
			    "'pap =' on line %d", sym_line);
	    }
	    sym_get();
	    continue;

#ifdef ACLS
	case S_acl:
	    ASSIGN(user->acl);
	    sym_get();
	    continue;

# ifdef UENABLE
	case S_enable:
	    sym_get();
	    parse(S_separator);

	    switch(sym_code) {
		case S_file:
		case S_cleartext:
		case S_des:
		    sprintf(buf, "%s ", sym_buf);
		    sym_get();
		    strcat(buf, sym_buf);
		    user->enable = tac_strdup(buf);
		    break;

		case S_nopasswd:
		    /* set to dummy string, so that we detect a duplicate
		     * password definition attempt
		     */
		    user->enable = tac_strdup(nopasswd_str);
		    user->noenablepwd = 1;
		    break;

#ifdef SKEY
		case S_skey:
		    user->enable = tac_strdup(sym_buf);
		    break;
#endif
#ifdef ACECLNT
		case S_aceclnt:
		    user->enable = tac_strdup(sym_buf);
		    break;
#endif

		default:
		    parse_error("expecting 'file', 'cleartext', 'nopassword', "
#ifdef SKEY
				"'skey', "
#endif
#ifdef ACECLNT
				"'aceclnt', "
#endif
				"or 'des' keyword after 'enable =' on line %d",
				sym_line);
	    }
	    sym_get();
	    continue;

	case S_enableacl:
	    ASSIGN(user->enableacl);
	    sym_get();
	    continue;
# endif
#endif

	case S_name:
	    ASSIGN(user->full_name);
	    sym_get();
	    continue;

	case S_member:
	    ASSIGN(user->member);
	    sym_get();
	    continue;

	case S_expires:
	    ASSIGN(user->expires);
	    sym_get();
	    continue;

	case S_message:
	    ASSIGN(user->msg);
	    sym_get();
	    continue;

	case S_arap:
	case S_chap:
#ifdef MSCHAP
	case S_mschap:
#endif /* MSCHAP */
	case S_opap:
	case S_global:
	    save_sym = sym_code;
	    sym_get();
	    parse(S_separator);
	    sprintf(buf, "%s ", sym_buf);
	    parse(S_cleartext);
	    strcat(buf, sym_buf);

	    if (save_sym == S_arap)
		fieldp = &user->arap;
	    if (save_sym == S_chap)
		fieldp = &user->chap;
#ifdef MSCHAP
	    if (save_sym == S_mschap)
		fieldp = &user->mschap;
#endif /* MSCHAP */
	    if (save_sym == S_pap)
		fieldp = &user->pap;
	    if (save_sym == S_opap)
		fieldp = &user->opap;
	    if (save_sym == S_global)
		fieldp = &user->global;

	    if (*fieldp) {
		parse_error("Duplicate value for %s %s and %s on line %d",
			    codestring(save_sym), *fieldp, sym_buf, sym_line);
		tac_exit(1);
	    }
	    *fieldp = tac_strdup(buf);
	    sym_get();
	    continue;

	case S_closebra:
	    parse(S_closebra);
	    return(0);

#ifdef MAXSESS
	case S_maxsess:
	    sym_get();
	    parse(S_separator);
	    if (sscanf(sym_buf, "%d", &user->maxsess) != 1) {
		parse_error("expecting integer, found '%s' on line %d",
		    sym_buf, sym_line);
	    }
	    sym_get();
	    continue;
#endif /* MAXSESS */

	default:
	    if (STREQ(sym_buf, "password")) {
		fprintf(stderr,
			"\npassword = <string> is obsolete. Use login = des <string>\n");
	    }
	    parse_error("Unrecognised keyword %s for user on line %d",
			sym_buf, sym_line);

	    return(0);
	}
    }
}

static NODE *
parse_svcs(void)
{
    NODE *result;

    switch (sym_code) {
    default:
	return(NULL);
    case S_svc:
    case S_cmd:
	break;
    }

    result = (NODE *)tac_malloc(sizeof(NODE));

    memset(result, 0, sizeof(NODE));
    result->line = sym_line;

    /* cmd declaration */
    if (sym_code == S_cmd) {
	parse(S_cmd);
	parse(S_separator);
	result->value = tac_strdup(sym_buf);

	sym_get();
	parse(S_openbra);

	result->value1 = parse_cmd_matches();
	result->type = N_svc_cmd;

	parse(S_closebra);
	result->next = parse_svcs();
	return(result);
    }

    /* svc declaration */
    parse(S_svc);
    parse(S_separator);
    switch (sym_code) {
    case S_string:
	result->type = N_svc;
	/* XXX should perhaps check that this is an allowable service name */
	result->value1 = tac_strdup(sym_buf);
	break;
    case S_exec:
	result->type = N_svc_exec;
	break;
    case S_arap:
	result->type = N_svc_arap;
	break;
    case S_slip:
	result->type = N_svc_slip;
	break;
    case S_ppp:
	result->type = N_svc_ppp;
	parse(S_ppp);
	parse(S_protocol);
	parse(S_separator);
	/* XXX Should perhaps check that this is a known PPP protocol name */
	result->value1 = tac_strdup(sym_buf);
	break;
    default:
	parse_error("expecting service type but found %s on line %d",
		    sym_buf, sym_line);
	return(NULL);
    }
    sym_get();
    parse(S_openbra);
    result->dflt = parse_opt_attr_default();
    result->value = parse_attrs();
    parse(S_closebra);
    result->next = parse_svcs();
    return(result);
}

/* <cmd-match>	 := <permission> <string> */
static NODE *
parse_cmd_matches(void)
{
    char buf[256];
    NODE *result;
    int ecode;

    if (sym_code != S_permit && sym_code != S_deny) {
	return(NULL);
    }
    result = (NODE *)tac_malloc(sizeof(NODE));

    memset(result, 0, sizeof(NODE));
    result->line = sym_line;

    result->type = (parse_permission() == S_permit) ? N_permit : N_deny;
    result->value = tac_strdup(sym_buf);

    result->value1 = tac_malloc(sizeof(regex_t));
    ecode = regcomp((regex_t *)result->value1, (char *)result->value,
		    (REG_EXTENDED | REG_NOSUB));
    if (ecode) {
	regerror(ecode, (regex_t *)result->value1, buf, 256);
	report(LOG_ERR, "in regex %s on line %d", sym_buf, sym_line);
	report(LOG_ERR, "regex compile failed: %s", buf);
	tac_exit(1);
    }
    sym_get();

    result->next = parse_cmd_matches();

    return(result);
}

static NODE *
parse_attrs(void)
{
    NODE *result;
    char buf[MAX_INPUT_LINE_LEN];
    int optional = 0;

    if (sym_code == S_closebra) {
	return(NULL);
    }
    result = (NODE *)tac_malloc(sizeof(NODE));

    memset(result, 0, sizeof(NODE));
    result->line = sym_line;

    if (sym_code == S_optional) {
	optional++;
	sym_get();
    }
    result->type = optional ? N_optarg : N_arg;

#ifdef ACLS
    /*
     * "acl" is an acceptable AV for service=exec and may as well be permitted
     * for any other service.  I did not know this when I defined "acl" for
     * connection ACLs.  So, hack it to be a string here.  If the parser were
     * half-way decent, acl just wouldnt be a keyword here.
     */
    if (sym_code == S_acl)
	sym_code = S_string;
#endif
    strcpy(buf, sym_buf);
    parse(S_string);
    strcat(buf, sym_buf);
    parse(S_separator);
    strcat(buf, sym_buf);
    parse(S_string);

    result->value = tac_strdup(buf);
    result->next = parse_attrs();
    return(result);
}

static void
sym_get(void)
{
    getsym();

    if (debug & DEBUG_PARSE_FLAG) {
	report(LOG_DEBUG, "line=%d sym=%s code=%d buf='%s'",
	       sym_line, codestring(sym_code), sym_code, sym_buf);
    }
}

static char *
sym_buf_add(char c)
{
    if (sym_pos >= MAX_INPUT_LINE_LEN) {
	sym_buf[MAX_INPUT_LINE_LEN-1] = '\0';
	if (debug & DEBUG_PARSE_FLAG) {
	    report(LOG_DEBUG, "line too long: line=%d sym=%s code=%d buf='%s'",
		   sym_line, codestring(sym_code), sym_code, sym_buf);
	}
	return(NULL);
    }

    sym_buf[sym_pos++] = c;
    return(sym_buf);
}

static void
getsym(void)
{

next:
    switch (sym_ch) {

    case EOF:
	sym_code = S_eof;
	return;

    case '\n':
	sym_line++;
	rch();
	goto next;

    case '\t':
    case ' ':
	while (sym_ch == ' ' || sym_ch == '\t')
	    rch();
	goto next;

    case '=':
	strcpy(sym_buf, "=");
	sym_code = S_separator;
	rch();
	return;

    case '{':
	strcpy(sym_buf, "{");
	sym_code = S_openbra;
	rch();
	return;

    case '}':
	strcpy(sym_buf, "}");
	sym_code = S_closebra;
	rch();
	return;

    case '#':
	while ((sym_ch != '\n') && (sym_ch != EOF))
	    rch();
	goto next;

    case '"':
	rch();
	sym_pos = 0;
	while (1) {

	    if (sym_ch == '"') {
		break;
	    }

	    /* backslash-double-quote is supported inside strings */
	    /* also allow \n */
	    if (sym_ch == '\\') {
		rch();
		switch (sym_ch) {
		case 'n':
		    /* preserve the slash for \n */
		    if (!sym_buf_add('\\')) {
			sym_code = S_unknown;
			rch();
			return;
		    }

		    /* fall through */
		case '"':
		case '\\':
		    if (!sym_buf_add(sym_ch)) {
			sym_code = S_unknown;
			rch();
			return;
		    }
		    rch();
		    continue;
		default:
		    sym_code = S_unknown;
		    rch();
		    return;
		}
	    }
	    if (!sym_buf_add(sym_ch)) {
		sym_code = S_unknown;
		rch();
		return;
	    }
	    rch();
	}
	rch();

	if (!sym_buf_add('\0')) {
	    sym_code = S_unknown;
	    rch();
	    return;
	}
	sym_code = S_string;
	return;

    default:
	sym_pos = 0;
	while (sym_ch != '\t' && sym_ch != ' ' && sym_ch != '='
	       && sym_ch != '\n') {

	    if (!sym_buf_add(sym_ch)) {
		sym_code = S_unknown;
		rch();
		return;
	    }
	    rch();
	}

	if (!sym_buf_add('\0')) {
	    sym_code = S_unknown;
	    rch();
	    return;
	}
	sym_code = keycode(sym_buf);
	if (sym_code == S_unknown)
	    sym_code = S_string;
	return;
    }
}

static void
rch(void)
{
    if (sym_error) {
	sym_ch = EOF;
	return;
    }
    sym_ch = getc(cf);

    if (parse_only && sym_ch != EOF)
	fprintf(stderr, "%c", sym_ch);
}

/* For a user or group, find the value of a field.  Does not recurse. */
static VALUE
get_value(USER *user, int field)
{
    VALUE v;

    memset(&v, 0, sizeof(VALUE));

    if (!user) {
	parse_error("get_value: illegal user");
	return(v);
    }
    switch (field) {
    case S_name:
	v.pval = user->name;
	break;

    case S_login:
	v.pval = user->login;
	break;

    case S_global:
	v.pval = user->global;
	break;

    case S_member:
	v.pval = user->member;
	break;

    case S_expires:
	v.pval = user->expires;
	break;

    case S_arap:
	v.pval = user->arap;
	break;

    case S_chap:
	v.pval = user->chap;
	break;

#ifdef MSCHAP
    case S_mschap:
	v.pval = user->mschap;
	break;
#endif /* MSCHAP */

#ifdef ACLS
    case S_acl:
	v.pval = user->acl;
	break;
# ifdef UENABLE
    case S_enable:
	v.pval = user->enable;
	break;
    case S_noenablepwd:
	v.intval = user->noenablepwd;
	break;
    case S_enableacl:
	v.pval = user->enableacl;
	break;
# endif
#endif

    case S_pap:
	v.pval = user->pap;
	break;

    case S_opap:
	v.pval = user->opap;
	break;

    case S_message:
	v.pval = user->msg;
	break;

    case S_svc:
	v.pval = user->svcs;
	break;

    case S_before:
	v.pval = user->before_author;
	break;

    case S_after:
	v.pval = user->after_author;
	break;

    case S_svc_dflt:
	v.intval = user->svc_dflt;
	break;

#ifdef MAXSESS
    case S_maxsess:
	v.intval = user->maxsess;
	break;
#endif

    case S_nopasswd:
	v.intval = user->nopasswd;
	break;

    default:
	report(LOG_ERR, "get_value: unknown field %d", field);
	break;
    }
    return(v);
}

/* For host, find value of field.  Is not recursive */
VALUE
get_hvalue(HOST *host, int field)
{
    VALUE v;

    memset(&v, 0, sizeof(VALUE));
    if (!host) {
	parse_error("get_hvalue: illegal host");
	return(v);
    }
    switch (field) {
	case S_name:
	    v.pval = host->name;
	    break;

	case S_key:
	    v.pval = host->key;
	    break;

	/* XXX
	case S_type:
	    v.pval = host->type;
	    break;
	 */

	case S_prompt:
	    v.pval = host->prompt;
	    break;

	case S_enable:
	    v.pval = host->enable;
	    break;

#ifdef UENABLE
	case S_noenablepwd:
	    v.intval = host->noenablepwd;
	    break;
#endif

	default:
	    report(LOG_ERR, "get_value: unknown field %d", field);
	    break;
    }
    return(v);
}

/*
 * For each user, check the user does not circularly reference a group.
 * Return 1 if it does.
 */
static int
circularity_check(void)
{
    USER *user, *entry, *group;
    USER **users = (USER **)hash_get_entries(usertable);
    USER **groups = (USER **)hash_get_entries(grouptable);
    USER **p, **q;

    /* users */
    for (p = users; *p; p++) {
	user = *p;

	if (debug & DEBUG_PARSE_FLAG)
	    report(LOG_DEBUG, "circularity_check: user=%s", user->name);

	/* Initialise all groups "seen" flags to zero */
	for (q = groups; *q; q++) {
	    group = *q;
	    group->flags &= ~FLAG_SEEN;
	}

	entry = user;

	while (entry) {
	    /* check groups we are a member of */
	    char *groupname = entry->member;

	    if (debug & DEBUG_PARSE_FLAG)
		report(LOG_DEBUG, "\tmember of group %s",
		       groupname ? groupname : "<none>");


	    /* if not a member of any groups, go on to next user */
	    if (!groupname)
		break;

	    group = (USER *)hash_lookup(grouptable, groupname);
	    if (!group) {
		report(LOG_ERR, "%s=%s, group %s does not exist",
		       (entry->flags & FLAG_ISUSER) ? "user" : "group",
		       entry->name, groupname);
		free(users);
		free(groups);
		return(1);
	    }
	    if (group->flags & FLAG_SEEN) {
		report(LOG_ERR, "recursively defined groups");

		/* print all seen "groups" */
		for (q = groups; *q; q++) {
		    group = *q;
		    if (group->flags & FLAG_SEEN)
			report(LOG_ERR, "%s", group->name);
		}
		free(users);
		free(groups);
		return(1);
	    }
	    group->flags |= FLAG_SEEN;	/* mark group as seen */
	    entry = group;
	}
    }
    free(users);
    free(groups);
    return(0);
}

/*
 * Return a value for a group or user (isuser says if this name is a group or
 * a user name).
 *
 * If no value exists, and recurse is true, also check groups the user is a
 * member of, recursively.
 *
 * Returns void * because it can return a string or a node pointer (should
 * really return a union pointer).
 */
static VALUE
cfg_get_value(char *name, int isuser, int attr, int recurse)
{
    USER *user, *group;
    VALUE value;

    memset(&value, 0, sizeof(VALUE));

    if (debug & DEBUG_CONFIG_FLAG)
	report(LOG_DEBUG, "cfg_get_value: name=%s isuser=%d attr=%s rec=%d",
	       name, isuser, codestring(attr), recurse);

    /* find the user/group entry */
    user = (USER *)hash_lookup(isuser ? usertable : grouptable, name);

    if (!user) {
	if (debug & DEBUG_CONFIG_FLAG)
	    report(LOG_DEBUG, "cfg_get_value: no user/group named %s", name);
        if (isuser && cfg_user_exists(DEFAULT_USERNAME)) {
            user = (USER *)hash_lookup(usertable, DEFAULT_USERNAME);
            report(LOG_DEBUG, "cfg_get_value: using DEFAULT");
        } else
            return(value);
    }

    /* found the entry. Lookup value from attr=value */
    value = get_value(user, attr);

    if (value.pval || !recurse) {
	return(value);
    }
    /* no value. Check containing group */
    if (user->member)
	group = (USER *)hash_lookup(grouptable, user->member);
    else
	group = NULL;

    while (group) {
	if (debug & DEBUG_CONFIG_FLAG)
	    report(LOG_DEBUG, "cfg_get_value: recurse group = %s", group->name);

	value = get_value(group, attr);
	if (value.pval) {
	    return(value);
	}
	/* still nothing. Check containing group and so on */

	if (group->member)
	    group = (USER *)hash_lookup(grouptable, group->member);
	else
	    group = NULL;
    }

    /* no value for this user or her containing groups */
    memset(&value, 0, sizeof(VALUE));
    return(value);
}

/* For getting host values */
static VALUE
cfg_get_hvalue(char *name, int attr)
{
    HOST *host;
    VALUE value;

    memset(&value, 0, sizeof(VALUE));

    if (debug & DEBUG_CONFIG_FLAG)
	report(LOG_DEBUG, "cfg_get_hvalue: name=%s attr=%s ",
							name, codestring(attr));

    /* find the host entry in hash table */
    host = (HOST *)hash_lookup(hosttable, name);

    if (!host) {
	if (debug & DEBUG_CONFIG_FLAG)
	    report(LOG_DEBUG, "cfg_get_hvalue: no host named %s", name);
	return(value);
    }

    /* found the entry. Lookup value from attr=value */
    value = get_hvalue(host, attr);

    if (value.pval)
	return(value);

    /* No any value for this host */
    memset(&value, 0, sizeof(VALUE));
    return(value);
}

/* Wrappers for cfg_get_value */
int
cfg_get_intvalue(char *name, int isuser, int attr, int recurse)
{
    int val;

    val = cfg_get_value(name, isuser, attr, recurse).intval;

    if (debug & DEBUG_CONFIG_FLAG)
	report(LOG_DEBUG, "cfg_get_intvalue: returns %d", val);
    return(val);
}

/* Wrappers for cfg_get_hvalue */
char *
cfg_get_phvalue(char *name, int attr)
{
    char *p;

    p = cfg_get_hvalue(name, attr).pval;

    if (debug & DEBUG_CONFIG_FLAG)
	report(LOG_DEBUG, "cfg_get_phvalue: returns %s", p ? p : "NULL");

    return(p);
}

char *
cfg_get_pvalue(char *name, int isuser, int attr, int recurse)
{
    char *p;

    p = cfg_get_value(name, isuser, attr, recurse).pval;

    if (debug & DEBUG_CONFIG_FLAG)
	report(LOG_DEBUG, "cfg_get_pvalue: returns %s",
	       p ? p : "NULL");

    return(p);
}

/*
 * Read the config file and do some basic sanity checking on it.  Return 1
 * if we find any errors.
 */
int
cfg_read_config(char *cfile)
{
    sym_line = 1;

    if ((cf = fopen(cfile, "r")) == NULL) {
	report(LOG_ERR, "read_config: fopen() error for file %s %s, exiting",
	       cfile, strerror(errno));
	return(1);
    }
    if (parse_decls() || sym_error) {
	fclose(cf);
	return(1);
    }

    if (circularity_check()) {
	fclose(cf);
	return(1);
    }

    fclose(cf);
    return(0);
}

/* return 1 if user exists, 0 otherwise */
int
cfg_user_exists(char *username)
{
    USER *user;

    user = (USER *)hash_lookup(usertable, username);

    return(user != NULL);
}

/*
 * return expiry string of user. If none, try groups she is a member
 * of, and so on, recursively if recurse is non-zero
 */
char *
cfg_get_expires(char *username, int recurse)
{
    return(cfg_get_pvalue(username, TAC_IS_USER, S_expires, recurse));
}

#ifdef ACLS
/*
 * check the acl against the provided ip.  return S_permit (succeed) if the
 * ip matches a permit, else S_deny (fail) if it matches a deny or does not
 * match any of the entries.
 */
int
cfg_acl_check(char *aclname, char *ip)
{
    NODE *next;
    ACL *acl;

    acl = (ACL *)hash_lookup(acltable, aclname);

    if (debug & DEBUG_AUTHEN_FLAG)
	report(LOG_DEBUG, "cfg_acl_check(%s, %s)", aclname, ip);

    if (acl == NULL) {
	report(LOG_ERR, "non-existent acl reference %s", aclname);
	return(S_deny);
    }

    next = acl->nodes;
    while (next) {
	if (regexec((regex_t *)next->value1, ip, 0, NULL, 0) == REG_OK) {
	    if (debug & DEBUG_AUTHEN_FLAG)
		report(LOG_DEBUG, "ip %s matched %s regex %s of acl filter %s",
			ip, next->type == S_deny ? "deny" : "permit",
			next->value, aclname);
	    return(next->type);
	}
	next = next->next;
    }

    /* default is fail (implicit deny) - ie: fell off the end */
    if (debug & DEBUG_AUTHEN_FLAG)
	report(LOG_DEBUG, "ip %s did not match in acl filter %s", ip, aclname);
    return(S_deny);
}
#endif

#if defined(UENABLE) || defined(SKEY)
/*
 * return enable password string of user.  If none, try groups user is a
 * member of, and so on, recursively if recurse is non-zero.
 */
char *
cfg_get_enable_secret(char *user, int recurse)
{
    return(cfg_get_pvalue(user, TAC_IS_USER, S_enable, recurse));
}
#endif

/* For getting host key */
char *
cfg_get_host_key(char *host)
{
    return(cfg_get_phvalue(host, S_key));
}

/* For getting host prompt */
char *
cfg_get_host_prompt(char *host)
{
    return(cfg_get_phvalue(host, S_prompt));
}

/* For getting host enable */
char *
cfg_get_host_enable(char *host)
{
    return(cfg_get_phvalue(host, S_enable));
}

#ifdef UENABLE
/*
 * return value of the noenablepwd field for the host.
 */
int
cfg_get_host_noenablepwd(char *host)
{
    return(cfg_get_hvalue(host, S_noenablepwd).intval);
}
#endif

/*
 * return password string of user.  If none, try groups the user is a member
 * of, and so on, recursively if recurse is non-zero.
 */
char *
cfg_get_login_secret(char *user, int recurse)
{
    return(cfg_get_pvalue(user, TAC_IS_USER, S_login, recurse));
}

#ifdef UENABLE
/*
 * return value of the noenablepwd field.  If none, try groups the user is a
 * member of, and so on, recursively if recurse is non-zero.
 */
int
cfg_get_user_noenablepwd(char *user, int recurse)
{
    return(cfg_get_intvalue(user, TAC_IS_USER, S_noenablepwd, recurse));
}
#endif

/*
 * return value of the nopasswd field.  If none, try groups the user is a
 * member of, and so on, recursively if recurse is non-zero.
 */
int
cfg_get_user_nopasswd(char *user, int recurse)
{
    return(cfg_get_intvalue(user, TAC_IS_USER, S_nopasswd, recurse));
}

/*
 * return the secret of the user.  If none, try groups the user is a member of,
 * and so on, recursively if recurse is non-zero.
 */
char *
cfg_get_arap_secret(char *user, int recurse)
{
    return(cfg_get_pvalue(user, TAC_IS_USER, S_arap, recurse));
}

char *
cfg_get_chap_secret(char *user, int recurse)
{
    return(cfg_get_pvalue(user, TAC_IS_USER, S_chap, recurse));
}

#ifdef MSCHAP
char *
cfg_get_mschap_secret(char *user, int recurse)
{
    return(cfg_get_pvalue(user, TAC_IS_USER, S_mschap, recurse));
}
#endif /* MSCHAP */

char *
cfg_get_pap_secret(char *user, int recurse)
{
    return(cfg_get_pvalue(user, TAC_IS_USER, S_pap, recurse));
}

char *
cfg_get_opap_secret(char *user, int recurse)
{
    return(cfg_get_pvalue(user, TAC_IS_USER, S_opap, recurse));
}

/* return the global password for the user (or the group, etc.) */
char *
cfg_get_global_secret(char *user, int recurse)
{
    return(cfg_get_pvalue(user, TAC_IS_USER, S_global, recurse));
}

/*
 * Return a pointer to a node representing a given service authorization,
 * taking care of recursion issues correctly.  Protocol is only read if the
 * type is N_svc_ppp. svcname is only read if type is N_svc.
 */
NODE *
cfg_get_svc_node(char *username, int type, char *protocol, char *svcname,
		 int recurse)
{
    USER *user, *group;
    NODE *svc;

    if (debug & DEBUG_CONFIG_FLAG)
	report(LOG_DEBUG,
	       "cfg_get_svc_node: username=%s %s proto=%s svcname=%s rec=%d",
	       username, cfg_nodestring(type), protocol ? protocol : "",
	       svcname ? svcname : "", recurse);

    /* find the user/group entry */
    user = (USER *)hash_lookup(usertable, username);

    if (!user) {
	if (debug & DEBUG_CONFIG_FLAG)
	    report(LOG_DEBUG, "cfg_get_svc_node: no user named %s", username);
	return(NULL);
    }

    /* found the user entry. Find svc node */
    for (svc = (NODE *)get_value(user, S_svc).pval; svc; svc = svc->next) {

	if (svc->type != type)
	    continue;

	if (type == N_svc_ppp && !STREQ(svc->value1, protocol)) {
	    continue;
	}

	if (type == N_svc && !STREQ(svc->value1, svcname)) {
	    continue;
	}

	if (debug & DEBUG_CONFIG_FLAG)
	    report(LOG_DEBUG,
		   "cfg_get_svc_node: found %s proto=%s svcname=%s",
		   cfg_nodestring(type),
		   protocol ? protocol : "",
		   svcname ? svcname : "");

	return(svc);
    }

    if (!recurse) {
	if (debug & DEBUG_CONFIG_FLAG)
	    report(LOG_DEBUG, "cfg_get_svc_node: returns NULL");
	return(NULL);
    }

    /* no matching node. Check containing group */
    if (user->member)
	group = (USER *)hash_lookup(grouptable, user->member);
    else
	group = NULL;

    while (group) {
	if (debug & DEBUG_CONFIG_FLAG)
	    report(LOG_DEBUG, "cfg_get_svc_node: recurse group = %s",
		   group->name);

	for (svc = (NODE *)get_value(group, S_svc).pval; svc; svc = svc->next) {

	    if (svc->type != type)
		continue;

	    if (type == N_svc_ppp && !STREQ(svc->value1, protocol)) {
		continue;
	    }

	    if (type == N_svc && !STREQ(svc->value1, svcname)) {
		continue;
	    }

	    if (debug & DEBUG_CONFIG_FLAG)
		report(LOG_DEBUG,
		       "cfg_get_svc_node: found %s proto=%s svcname=%s",
		       cfg_nodestring(type), protocol ? protocol : "",
		       svcname ? svcname : "");

	    return(svc);
	}

	/* still nothing. Check containing group and so on */

	if (group->member)
	    group = (USER *)hash_lookup(grouptable, group->member);
	else
	    group = NULL;
    }

    if (debug & DEBUG_CONFIG_FLAG)
	report(LOG_DEBUG, "cfg_get_svc_node: returns NULL");

    /* no matching svc node for this user or her containing groups */
    return(NULL);
}

/*
 * Return a pointer to the node representing a set of command regexp matches
 * for a user and command, handling recursion issues correctly.
 */
NODE *
cfg_get_cmd_node(char *name, char *cmdname, int recurse)
{
    USER *user, *group;
    NODE *svc;

    if (debug & DEBUG_CONFIG_FLAG)
	report(LOG_DEBUG, "cfg_get_cmd_node: name=%s cmdname=%s rec=%d",
	       name, cmdname, recurse);

    /* find the user/group entry */
    user = (USER *)hash_lookup(usertable, name);

    if (!user) {
	if (debug & DEBUG_CONFIG_FLAG)
	    report(LOG_DEBUG, "cfg_get_cmd_node: no user named %s", name);
	return(NULL);
    }
    /* found the user entry. Find svc node */
    svc = (NODE *)get_value(user, S_svc).pval;

    while (svc) {
	if (svc->type == N_svc_cmd && STREQ(svc->value, cmdname)) {
	    if (debug & DEBUG_CONFIG_FLAG)
		report(LOG_DEBUG, "cfg_get_cmd_node: found cmd %s %s node",
		       cmdname, cfg_nodestring(svc->type));
	    return(svc);
	}
	svc = svc->next;
    }

    if (!recurse) {
	if (debug & DEBUG_CONFIG_FLAG)
	    report(LOG_DEBUG, "cfg_get_cmd_node: returns NULL");
	return(NULL);
    }
    /* no matching node. Check containing group */
    if (user->member)
	group = (USER *)hash_lookup(grouptable, user->member);
    else
	group = NULL;

    while (group) {
	if (debug & DEBUG_CONFIG_FLAG)
	    report(LOG_DEBUG, "cfg_get_cmd_node: recurse group = %s",
		   group->name);

	svc = get_value(group, S_svc).pval;

	while (svc) {
	    if (svc->type == N_svc_cmd && STREQ(svc->value, cmdname)) {
		if (debug & DEBUG_CONFIG_FLAG)
		    report(LOG_DEBUG, "cfg_get_cmd_node: found cmd %s node %s",
			   cmdname, cfg_nodestring(svc->type));
		return(svc);
	    }
	    svc = svc->next;
	}

	/* still nothing. Check containing group and so on */

	if (group->member)
	    group = (USER *)hash_lookup(grouptable, group->member);
	else
	    group = NULL;
    }

    if (debug & DEBUG_CONFIG_FLAG)
	report(LOG_DEBUG, "cfg_get_cmd_node: returns NULL");

    /* no matching cmd node for this user or her containing groups */
    return(NULL);
}

/*
 * Return an array of character strings representing configured AV
 * pairs, given a username and a service node.
 *
 * In the AV strings returned, manipulate the separator character to
 * indicate which args are optional and which are mandatory.
 *
 * Lastly, indicate what default permission was configured by setting denyp
 */
char **
cfg_get_svc_attrs(NODE *svcnode, int *denyp)
{
    int i;
    NODE *node;
    char **args;

    *denyp = 1;

    if (!svcnode)
	return(NULL);

    *denyp = (svcnode->dflt == S_deny);

    i = 0;
    for (node = svcnode->value; node; node = node->next)
	i++;

    args = (char **)tac_malloc(sizeof(char *) * (i + 1));

    i = 0;
    for (node = svcnode->value; node; node = node->next) {
	char *arg = tac_strdup(node->value);
	char *p = strchr(arg, '=');

	if (p && node->type == N_optarg)
	    *p = '*';
	args[i++] = arg;
    }
    args[i] = NULL;
    return(args);
}

int
cfg_user_svc_default_is_permit(char *user)
{
    int permit;

    permit = cfg_get_intvalue(user, TAC_IS_USER, S_svc_dflt, TAC_PLUS_RECURSE);

    switch (permit) {
    default:			/* default is deny */
    case S_deny:
	return(0);
    case S_permit:
	return(1);
    }
}

int
cfg_get_maxprocs(void)
{
    return(maxprocs);
}

int
cfg_get_maxprocsperclt(void)
{
    return(maxprocsperclt);
}

int
cfg_get_readtimeout(void)
{
    return(readtimeout);
}

int
cfg_get_writetimeout(void)
{
    return(writetimeout);
}

int
cfg_get_accepttimeout(void)
{
    return(accepttimeout);
}

int
cfg_get_logauthor(void)
{
  return(logauthor);
}

char *
cfg_get_authen_default(void)
{
    return(authen_default);
}

/*
 * Return 1 if this user has any ppp services configured. Used for
 * authorizing ppp/lcp requests
 */
int
cfg_ppp_is_configured(char *username, int recurse)
{
    USER *user, *group;
    NODE *svc;

    if (debug & DEBUG_CONFIG_FLAG)
	report(LOG_DEBUG, "cfg_ppp_is_configured: username=%s rec=%d",
	       username, recurse);

    /* find the user/group entry */
    user = (USER *)hash_lookup(usertable, username);

    if (!user) {
	if (debug & DEBUG_CONFIG_FLAG)
	    report(LOG_DEBUG, "cfg_ppp_is_configured: no user named %s",
		   username);
	return(0);
    }

    /* found the user entry. Find svc node */
    for (svc = (NODE *)get_value(user, S_svc).pval; svc; svc = svc->next) {

	if (svc->type != N_svc_ppp)
	    continue;

	if (debug & DEBUG_CONFIG_FLAG)
	    report(LOG_DEBUG, "cfg_ppp_is_configured: found svc ppp %s node",
		   svc->value1);

	return(1);
    }

    if (!recurse) {
	if (debug & DEBUG_CONFIG_FLAG)
	    report(LOG_DEBUG, "cfg_ppp_is_configured: returns 0");
	return(0);
    }

    /* no matching node. Check containing group */
    if (user->member)
	group = (USER *)hash_lookup(grouptable, user->member);
    else
	group = NULL;

    while (group) {
	if (debug & DEBUG_CONFIG_FLAG)
	    report(LOG_DEBUG, "cfg_ppp_is_configured: recurse group = %s",
		   group->name);

	for (svc = (NODE *)get_value(group, S_svc).pval; svc; svc = svc->next) {

	    if (svc->type != N_svc_ppp)
		continue;

	    if (debug & DEBUG_CONFIG_FLAG)
		report(LOG_DEBUG, "cfg_ppp_is_configured: found svc ppp %s "
		       "node", svc->value1);

	    return(1);
	}

	/* still nothing. Check containing group and so on */

	if (group->member)
	    group = (USER *)hash_lookup(grouptable, group->member);
	else
	    group = NULL;
    }

    if (debug & DEBUG_CONFIG_FLAG)
	report(LOG_DEBUG, "cfg_ppp_is_configured: returns 0");

    /* no PPP svc nodes for this user or her containing groups */
    return(0);
}
