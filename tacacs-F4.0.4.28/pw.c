/*
 * $Id: pw.c,v 1.7 2009-03-18 17:48:59 heas Exp $
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

/*
 * Tacacs+ password lookup routine for those systems which don't have
 * setpwfile.  Not for use on /etc/passwd files.
 */

#include "tac_plus.h"
#include <pwd.h>
#include <string.h>

static struct passwd pw_passwd;

struct passwd *
tac_passwd_lookup(char *name, char *file)
{
    FILE *passwd_fp = NULL;

    static char uname[512];
    static char password[1024];
    static char gecos[1024];
    static char homedir[1024];
    static char shell[1024];
    char buf[1024];
    char *s, *e;

    passwd_fp = fopen(file, "r");

    if (passwd_fp) {
	if (debug & DEBUG_PASSWD_FLAG)
	    report(LOG_DEBUG, "tac_passwd_lookup: open %s %d",
		   file, fileno(passwd_fp));
    } else {
	report(LOG_ERR, "tac_passwd_lookup: cannot open file %s for reading",
	       file);
	return(NULL);
    }

    while (fgets(buf, sizeof(buf), passwd_fp)) {

	/* uname, password, uid, gid, gecos, homedir, shell */

	s = buf;
	e = strchr(buf, ':');
	if (!e)
	    break;

	strncpy(uname, s, e - s);
	uname[e - s] = '\0';

	/* try next entry */
	if (strcmp(uname, name))
	    continue;

	s = e + 1;
	e = strchr(s, ':');
	if (!e) {
	    break;
	}
	strncpy(password, s, e - s);
	password[e - s] = '\0';

	s = e + 1;
	e = strchr(s, ':');
	if (!e) {
	    break;
	}
	pw_passwd.pw_uid = atoi(s);

	s = e + 1;
	e = strchr(s, ':');
	pw_passwd.pw_gid = atoi(s);

	s = e + 1;
	e = strchr(s, ':');
	if (!e) {
	    break;
	}
	strncpy(gecos, s, e - s);
	gecos[e - s] = '\0';

	s = e + 1;
	e = strchr(s, ':');
	if (!e) {
	    break;
	}
	strncpy(homedir, s, e - s);
	homedir[e - s] = '\0';

	s = e + 1;
	e = strchr(s, '\n');
	if (!e) {
	    break;
	}
	strncpy(shell, s, e - s);
	shell[e - s] = '\0';

	pw_passwd.pw_name    = uname;
	pw_passwd.pw_passwd  = password;
#ifndef NO_PWAGE
	pw_passwd.pw_age     = NULL;
	pw_passwd.pw_comment = NULL;
#endif /* NO_PWAGE */
	pw_passwd.pw_gecos   = gecos;
	pw_passwd.pw_dir     = homedir;
	pw_passwd.pw_shell   = shell;

	if (debug & DEBUG_PASSWD_FLAG)
	    report(LOG_DEBUG, "tac_passwd_lookup: close %s %d",
		   file, fileno(passwd_fp));
	fclose(passwd_fp);
	return(&pw_passwd);
    }

    /* no match found */
    if (debug & DEBUG_PASSWD_FLAG)
	    report(LOG_DEBUG, "tac_passwd_lookup: close %s %d",
		   file, fileno(passwd_fp));
    fclose(passwd_fp);

    return(NULL);
}
