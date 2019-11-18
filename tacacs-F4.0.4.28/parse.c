/*
 * $Id: parse.c,v 1.15 2009-03-17 18:40:20 heas Exp $
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

/* Keywords of the configuration language */

#include "tac_plus.h"

static void *wordtable[HASH_TAB_SIZE];	/* Table of keyword declarations */

struct keyword {
    char *word;
    void *hash;
    u_char value;
};

typedef struct keyword KEYWORD;

static void declare(char *, int);

static void
declare(char *name, int value)
{
    KEYWORD *n;
    KEYWORD *k = (KEYWORD *)tac_malloc(sizeof(KEYWORD));

    k->word = tac_strdup(name);
    k->value = value;

    n = hash_add_entry(wordtable, (void *) k);

    if (n) {
	report(LOG_ERR, "Attempt to multiply define keyword %s", name);
	tac_exit(1);
    }
}

/* Declare keywords of the "configuration language". */
void
parser_init(void)
{
    memset(wordtable, 0, sizeof(wordtable));

    declare("access", S_access);
    declare("accounting", S_accounting);
#ifdef ACECLNT
    declare("aceclnt", S_aceclnt);
#endif
#ifdef ACLS
    declare("acl", S_acl);
#endif
    declare("after", S_after);
    declare("arap", S_arap);
    declare("attribute", S_attr);
    declare("authentication", S_authentication);
    declare("authorization", S_authorization);
    declare("before", S_before);
    declare("chap", S_chap);
#ifdef MSCHAP
    declare("ms-chap", S_mschap);
#endif /* MSCHAP */
    declare("cleartext", S_cleartext);
    declare("nopassword", S_nopasswd);
    declare("cmd", S_cmd);
    declare("default", S_default);
    declare("deny", S_deny);
    declare("des", S_des);
    declare("enable", S_enable);
#ifdef UENABLE
    declare("enableacl", S_enableacl);
#endif
    declare("exec", S_exec);
    declare("expires", S_expires);
    declare("external", S_external);
    declare("file", S_file);
    declare("group", S_group);
    declare("global", S_global);
    declare("host", S_host);
    declare("ip", S_ip);
    declare("ipx", S_ipx);
    declare("key", S_key);
    declare("lcp", S_lcp);
#ifdef MAXSESS
    declare("maxsess", S_maxsess);
#endif
    declare("member", S_member);
    declare("message", S_message);
    declare("name", S_name);
    declare("optional", S_optional);
    declare("login", S_login);
    declare("permit", S_permit);
    declare("pap", S_pap);
    declare("opap", S_opap);
    declare("ppp", S_ppp);
    declare("protocol", S_protocol);
#ifdef SKEY
    declare("skey", S_skey);
#endif
    declare("slip", S_slip);
    declare("service", S_svc);
    declare("user", S_user);
    declare("prompt", S_prompt);
    declare("logging", S_logging);
#ifdef HAVE_PAM
    declare("PAM", S_pam);
#endif
    declare("syslog", S_syslog);
    declare("maxprocs", S_maxprocs);
    declare("maxprocsperclt", S_maxprocsperclt);
    declare("readtimeout", S_readtimeout);
    declare("writetimeout", S_writetimeout);
    declare("accepttimeout", S_accepttimeout);
    declare("logauthor", S_logauthor);

}

/* Return a keyword code if a keyword is recognized. 0 otherwise */
int
keycode(char *keyword)
{
    KEYWORD *k = hash_lookup(wordtable, keyword);

    if (k)
	return(k->value);
    return(S_unknown);
}

char *
codestring(int type)
{
    switch (type) {
    default:
	return("<unknown symbol>");
    case S_eof:
	return("end-of-file");
    case S_unknown:
	return("unknown");
    case S_separator:
	return("=");
    case S_string:
	return("<string>");
    case S_openbra:
	return("{");
    case S_closebra:
	return("}");
#ifdef ACLS
    case S_acl:
	return("acl");
#endif
    case S_enable:
	return("enable");
#ifdef UENABLE
    case S_enableacl:
	return("enableacl");
#endif
    case S_key:
	return("key");
    case S_user:
	return("user");
    case S_group:
	return("group");
    case S_host:
	return("host");
    case S_file:
	return("file");
#ifdef SKEY
    case S_skey:
	return("skey");
#endif
#ifdef ACECLNT
    case S_aceclnt:
	return("aceclnt");
#endif
    case S_name:
	return("name");
    case S_login:
	return("login");
    case S_member:
	return("member");
#ifdef MAXSESS
    case S_maxsess:
	return("maxsess");
#endif
    case S_expires:
	return("expires");
    case S_after:
	return("after");
    case S_before:
	return("before");
    case S_message:
	return("message");
    case S_arap:
	return("arap");
    case S_global:
	return("global");
    case S_chap:
	return("chap");
#ifdef MSCHAP
    case S_mschap:
	return("ms-chap");
#endif /* MSCHAP */
    case S_pap:
	return("pap");
    case S_opap:
	return("opap");
    case S_cleartext:
	return("cleartext");
    case S_nopasswd:
	return("nopassword");
    case S_des:
	return("des");
    case S_external:
	return("external");
    case S_svc:
	return("service");
    case S_default:
	return("default");
    case S_access:
	return("access");
    case S_deny:
	return("deny");
    case S_permit:
	return("permit");
    case S_exec:
	return("exec");
    case S_protocol:
	return("protocol");
    case S_optional:
	return("optional");
    case S_ip:
	return("ip");
    case S_ipx:
	return("ipx");
    case S_slip:
	return("slip");
    case S_ppp:
	return("ppp");
    case S_authentication:
	return("authentication");
    case S_authorization:
	return("authorization");
    case S_cmd:
	return("cmd");
    case S_attr:
	return("attribute");
    case S_svc_dflt:
	return("svc_dflt");
    case S_accounting:
	return("accounting");
    case S_lcp:
	return("lcp");
    case S_prompt:
	return("prompt");
    case S_logging:
	return("logging");
#ifdef HAVE_PAM
    case S_pam:
	return("PAM");
#endif
    case S_syslog:
	return("syslog");
    case S_maxprocs:
  return("maxprocs");
    case S_maxprocsperclt:
  return("maxprocsperclt");
    case S_readtimeout:
  return("readtimeout");
    case S_writetimeout:
  return("writetimeout");
    case S_accepttimeout:
  return("accepttimeout");
    case S_logauthor:
  return("logauthor");
    }
}
