/*
 * $Id: report.c,v 1.16 2009-07-16 16:58:23 heas Exp $
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
#include "pathsl.h"
#include <stdio.h>

#ifdef AIX
#include <sys/types.h>
#else
#include <time.h>
#endif

#ifdef __STDC__
#include <stdarg.h>		/* ANSI C, variable length args */
#else
#include <varargs.h>		/* has 'vararg' definitions */
#endif

FILE *ostream = NULL;

/* report:
 *
 * This routine reports errors and such via stderr and syslog() if
 * appopriate.  It just helps avoid a lot of if-else in the code.
 *
 * LOG_DEBUG messages are ignored unless debugging is on.
 * All other priorities are always logged to syslog.
 */
#ifdef __STDC__
void
report(int priority, char *fmt, ...)
#else
/* VARARGS2 */
void
report(priority, fmt, va_alist)
    int priority;
    char *fmt;
    va_dcl				/* no terminating semi-colon */
#endif
{
    char msg[255];		/* temporary string */
    char *fp, *bufp, *charp;
    int len, m, i, n;
    char digits[16];
    va_list ap;

    charp = NULL;
    m = 0;

#ifdef __STDC__
    va_start(ap, fmt);
#else
    va_start(ap);
#endif

    /* ensure that msg is never overwritten */
    n = 255;
    fp = fmt;
    len = 0;
    msg[n-1] = '\0';
    bufp = msg;

    while (*fp) {

	if (*fp != '%') {
	    if ((len+1) >= n) {
		break;
	    }
	    *bufp++ = *fp++;
	    len++;
	    continue;
	}

	/* seen a '%' */
	fp++;

	switch (*fp) {

	case 's':
	    fp++;
	    charp = va_arg(ap, char *);
	    m = strlen(charp);
	    break;

	case 'u':
	    fp++;
	    i = va_arg(ap, uint);
	    sprintf(digits, "%u", i);
	    m = strlen(digits);
	    charp = digits;
	    break;
	case 'x':
	    fp++;
	    i = va_arg(ap, uint);
	    sprintf(digits, "%x", i);
	    m = strlen(digits);
	    charp = digits;
	    break;
	case 'd':
	    fp++;
	    i = va_arg(ap, int);
	    sprintf(digits, "%d", i);
	    m = strlen(digits);
	    charp = digits;
	    break;
	}

	if ((len + m + 1) >= n) {
	    break;
	}

	memcpy(bufp, charp, m);
	bufp += m;
	len += m;
	continue;
    }

    msg[len] = '\0';

    /* check we never overwrote the end of the buffer */
    if (msg[n-1]) {
	abort();
    }

    va_end(ap);


    if (console) {
	if (!ostream)
	    ostream = fopen("/dev/console", "w");

	if (ostream) {
	    if (priority == LOG_ERR)
		fprintf(ostream, "Error ");
	    fprintf(ostream, "%s\n", msg);
	} else
	    syslog(LOG_ERR, "Cannot open /dev/console errno=%d", errno);
    }

    if (debug) {
	int logfd;

	logfd = open(TACPLUS_LOGFILE, O_CREAT | O_WRONLY | O_APPEND, 0644);
	if (logfd >= 0) {
	    char buf[512];
	    time_t t = time(NULL);
	    char *ct = ctime(&t);

	    ct[24] = '\0';
	    tac_lockfd(TACPLUS_LOGFILE, logfd);
	    sprintf(buf, "%s [%ld]: ", ct, (long)getpid());
	    write(logfd, buf, strlen(buf));
	    if (priority == LOG_ERR)
		write(logfd, "Error ", 6);
	    write(logfd, msg, strlen(msg));
	    write(logfd, "\n", 1);
	    close(logfd);
	}
    }

    if (single) {
	fprintf(stderr, "%s\n", msg);
    }

    if (priority == LOG_ERR)
	syslog(priority, "Error %s", msg);
    else
	syslog(priority, "%s", msg);
}

/* format a hex dump for syslog */
void
report_hex(int priority, u_char *p, int len)
{
    char buf[256];
    char digit[10];
    int buflen;
    int i;

    if (len <= 0)
	return;

    buf[0] = '\0';
    buflen = 0;
    for (i = 0; i < len && i < 255; i++, p++) {

	sprintf(digit, "0x%x ", *p);
	strcat(buf, digit);
	buflen += strlen(digit);

	if (buflen > 75) {
	    report(priority, "%s", buf);
	    buf[0] = '\0';
	    buflen = 0;
	}
    }

    if (buf[0]) {
	report(priority, "%s", buf);
    }

    return;
}

/* format a non-null terminated string for syslog */
void
report_string(int priority, u_char *p, int len)
{
    char buf[256];
    char *bufp = buf;
    int i, n;

    if (len <= 0)
	return;

    if (len > 255)
	len = 255;

    for (i = 0; i < len; i++) {
	/* ASCII printable, else ... */
	if (32 <= *p && *p <= 126) {
	    *bufp++ = *p++;
	} else {
	    n = snprintf(bufp, len - i, " 0x%x ", *p);
	    if (n >= len - i)
		break;
	    bufp += n;
	    i += n - 1;
	    p++;
	}
    }
    *bufp = '\0';
    report(priority, "%s", buf);
}

void
regerror(char *s)
{
    report(LOG_ERR, "in regular expression %s", s);
}
