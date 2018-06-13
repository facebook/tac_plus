/*
 * $Id: maxsess.c,v 1.12 2009-07-16 18:13:19 heas Exp $
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

#if HAVE_CTYPE_H
# include <ctype.h>
#endif
#include <poll.h>
#include <signal.h>

char *wholog = TACPLUS_WHOLOGFILE;

static int timed_read(int, unsigned char *, int, int);

/*
 * initialize wholog file for tracking of user logins/logouts from
 * accounting records.
 */
void
maxsess_loginit(void)
{
    int fd;

    fd = open(wholog, O_CREAT | O_RDWR, 0600);
    if (fd < 0) {
	report(LOG_ERR, "Can't create: %s", wholog);
    } else {
	if (debug & DEBUG_MAXSESS_FLAG) {
	    report(LOG_DEBUG, "Initialize %s", wholog);
	}
	close(fd);
    }
}

/*
 * Given a port description, return it in a canonical format.
 *
 * This piece of goo is to cover the fact that an async line in EXEC
 * mode is known as "ttyXX", but the same line doing PPP or SLIP is
 * known as "AsyncXX".
 */
static char *
portname(char *oldport)
{
    char *p = oldport;

    if (!strncmp(p, "Async", 5) || !strncmp(p, "tty", 3)) {
	while (!isdigit((int) *p) && *p) {
	    ++p;
	}
    }
    if (!*p) {
	if (debug & DEBUG_ACCT_FLAG)
	    report(LOG_DEBUG, "Maxsess -- Malformed portname: %s", oldport);
	return(oldport);
    }
    return(p);
}

/*
 * Seek to offset and write a buffer into the file pointed to by fp
 */
static void
write_record(char *name, FILE *fp, void *buf, int size, long offset)
{
    if (fseek(fp, offset, SEEK_SET) < 0) {
	report(LOG_ERR, "%s fd=%d Cannot seek to %d %s",
	       name, fileno(fp), offset, strerror(errno));
    }
    if (fwrite(buf, size, 1, fp) != 1) {
	report(LOG_ERR, "%s fd=%d Cannot write %d bytes",
	       name, fileno(fp), size);
    }
}

static void
process_stop_record(struct identity *idp)
{
    int recnum;
    struct peruser pu;
    FILE *fp;
    char *nasport = portname(idp->NAS_port);

    /* If we can't access the file, skip all checks. */
    fp = fopen(wholog, "r+");
    if (fp == NULL) {
	report(LOG_ERR, "Can't open %s for updating", wholog);
	return;
    }
    tac_lockfd(wholog, fileno(fp));

    for (recnum = 0; 1; recnum++) {
	fseek(fp, recnum * sizeof(struct peruser), SEEK_SET);

	if (fread(&pu, sizeof(pu), 1, fp) <= 0) {
	    break;
	}

	/* A match for this record? */
	if (!(STREQ(pu.NAS_name, idp->NAS_name) &&
	    STREQ(pu.NAS_port, nasport))) {
	    continue;
	}

	/* A match. Zero out this record */
	memset(&pu, 0, sizeof(pu));

	write_record(wholog, fp, &pu, sizeof(pu),
		     recnum * sizeof(struct peruser));

	if (debug & DEBUG_MAXSESS_FLAG) {
	    report(LOG_DEBUG, "STOP record -- clear %s entry %d for %s/%s",
		   wholog, recnum, idp->username, nasport);
	}
    }
    fclose(fp);
}

static void
process_start_record(struct identity *idp)
{
    int recnum;
    int foundrec = -1;
    int freerec = -1;
    char *nasport = portname(idp->NAS_port);
    struct peruser pu;
    FILE *fp;

    /* If we can't access the file, skip all checks. */
    fp = fopen(wholog, "r+");
    if (fp == NULL) {
	report(LOG_ERR, "Can't open %s for updating", wholog);
	return;
    }
    tac_lockfd(wholog, fileno(fp));

    for (recnum = 0; (fread(&pu, sizeof(pu), 1, fp) > 0); recnum++) {
	/* Match for this NAS/Port record? */
	if (STREQ(pu.NAS_name, idp->NAS_name) && STREQ(pu.NAS_port, nasport)) {
	    foundrec = recnum;
	    break;
	}
	/* Found a free slot on the way */
	if (pu.username[0] == '\0') {
	    freerec = recnum;
	}
    }

    /*
     * This is a START record, so write a new record or update the existing
     * one.  Note that we zero the memory, so the strncpy()'s will truncate
     * long names and always leave a null-terminated string.
     */
    memset(&pu, 0, sizeof(pu));
    strncpy(pu.username, idp->username, sizeof(pu.username) - 1);
    strncpy(pu.NAS_name, idp->NAS_name, sizeof(pu.NAS_name) - 1);
    strncpy(pu.NAS_port, nasport, sizeof(pu.NAS_port) - 1);
    strncpy(pu.NAC_address, idp->NAC_address, sizeof(pu.NAC_address) - 1);

    /* Already in DB? */
    if (foundrec >= 0) {
	if (debug & DEBUG_MAXSESS_FLAG) {
	    report(LOG_DEBUG,
		   "START record -- overwrite existing %s entry %d for %s "
		   "%s/%s", wholog, foundrec, pu.NAS_name, pu.username,
		   pu.NAS_port);
	}
	write_record(wholog, fp, &pu, sizeof(pu),
		     foundrec * sizeof(struct peruser));
	fclose(fp);
	return;
    }

    /* Not found in DB, but we have a free slot */
    if (freerec >= 0) {

	write_record(wholog, fp, &pu, sizeof(pu),
		     freerec * sizeof(struct peruser));

	if (debug & DEBUG_MAXSESS_FLAG) {
	    report(LOG_DEBUG, "START record -- %s entry %d for %s %s/%s added",
		   wholog, freerec, pu.NAS_name, pu.username, pu.NAS_port);
	}
	fclose(fp);
	return;
    }

    /* No free slot. Add record at the end */
    write_record(wholog, fp, &pu, sizeof(pu),
		 recnum * sizeof(struct peruser));

    if (debug & DEBUG_MAXSESS_FLAG) {
	report(LOG_DEBUG, "START record -- %s entry %d for %s %s/%s added",
	       wholog, recnum, pu.NAS_name, pu.username, pu.NAS_port);
    }
    fclose(fp);
}

/*
 * Given a start or a stop accounting record, update the file of
 * records which tracks who's logged on and where.
 */
void
loguser(struct acct_rec *rec)
{
    struct identity *idp;
    int i;

    /* We're only interested in start/stop records */
    if ((rec->acct_type != ACCT_TYPE_START) &&
	(rec->acct_type != ACCT_TYPE_STOP)) {
	return;
    }
    /* ignore command accounting records */
    for (i = 0; i < rec->num_args; i++) {
	char *avpair = rec->args[i];
	if ((strncmp(avpair, "cmd=", 4) == 0) && strlen(avpair) > 4) {
	    return;
	}
    }

    /* Extract and store just the port number, since the port names are
     * different depending on whether this is an async interface or an exec
     * line. */
    idp = rec->identity;

    switch (rec->acct_type) {
    case ACCT_TYPE_START:
	process_start_record(idp);
	return;

    case ACCT_TYPE_STOP:
	process_stop_record(idp);
	return;
    }
}

/*
 * Read up to n bytes from descriptor fd into array ptr with timeout t
 * seconds.
 *
 * Return -1 on error, eof or timeout. Otherwise return number of bytes read.
 */
static int
timed_read(int fd, unsigned char *ptr, int nbytes, int timeout)
{
    int nread;
    struct pollfd pfds;

    pfds.fd = fd;
    pfds.events = POLLIN | POLLERR | POLLHUP | POLLNVAL;

    while (1) {
	int status = poll(&pfds, 1, timeout * 1000);

	if (status == 0) {
	    status = errno;
	    report(LOG_DEBUG, "%s: timeout reading fd %d", session.peer, fd);
	    errno = status;
	    return(-1);
	}
	if (status < 0) {
	    if (errno == EINTR)
		continue;
	    status = errno;
	    report(LOG_DEBUG, "%s: error in poll %s fd %d", session.peer,
		   strerror(errno), fd);
	    errno = status;
	    return(-1);
	}
	if (pfds.revents & (POLLERR | POLLHUP | POLLNVAL)) {
	    status = errno;
	    report(LOG_DEBUG, "%s: exception on fd %d", session.peer, fd);
	    errno = status;
	    return(-1);
	}
	if (!(pfds.revents & POLLIN)) {
	    status = errno;
	    report(LOG_DEBUG, "%s: spurious return from poll", session.peer);
	    errno = status;
	    continue;
	}
	nread = read(fd, ptr, nbytes);

	if (nread < 0) {
	    if (errno == EINTR) {
		continue;
	    }
	    status = errno;
	    report(LOG_DEBUG, "%s %s: error reading fd %d nread=%d %s",
		   session.peer, session.port, fd, nread, strerror(errno));
	    errno = status;
	    return(-1);		/* error */
	}
	if (nread == 0) {
	    errno = 0;
	    return(-1);		/* eof */
	}
	return(nread);
    }
    /* NOTREACHED */
}

/*
 * Contact a NAS (using finger) to check how many sessions this USER
 * is currently running on it.
 *
 * Note that typically you run this code when you are in the middle of
 * trying to login to a Cisco NAS on a given port. Because you are
 * part way through a login when you do this, you can get inconsistent
 * reports for that particular port about whether the user is
 * currently logged in on it or not, so we ignore output which claims
 * that the user is using that line currently.
 *
 * This is extremely Cisco specific -- finger formats appear to vary wildly.
 * The format we're expecting is:

    Line     User      Host(s)		    Idle Location
   0 con 0	       idle		    never
  18 vty 0   usr0      idle		       30 barley.cisco.com
  19 vty 1   usr0      Virtual Exec		2
  20 vty 2	       idle			0 barley.cisco.com

 * Column zero contains a space or an asterisk character.  The line number
 * starts at column 1 and is 3 digits wide.  User names start at column 13,
 * with a maximum possible width of 10.
 *
 * Returns the number of sessions/connections, or zero on error.
 */
static int
ckfinger(char *user, char *nas, struct identity *idp)
{
    struct addrinfo hints, *res, *resp;
    int count, s, bufsize, ecode;
    char *buf, *p, *pn;
    int incr = 4096, slop = 32;
    char *curport = portname(idp->NAS_port);
    char *name;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if ((ecode = getaddrinfo(nas, "finger", &hints, &res)) != 0) {
	report(LOG_ERR, "ckfinger: getaddrinfo %s failure: %s", nas,
	       gai_strerror(ecode));
	return(0);
    }

    ecode = 0;
    for (resp = res; resp != NULL; resp = resp->ai_next) {
	s = socket(resp->ai_family, resp->ai_socktype, resp->ai_protocol);
	if (s < 0) {
	    if (errno == EAFNOSUPPORT || errno == EPROTONOSUPPORT)
		continue;
	    report(LOG_ERR, "ckfinger: socket: %s", strerror(errno));
	    freeaddrinfo(res);
	    return(0);
	}
	if ((ecode = connect(s, resp->ai_addr, res->ai_addrlen)) < 0) {
	    close(s);
	    continue;
	} else
	    break;
    }
    freeaddrinfo(res);
    /* socket failure / no supported address families */
    if (resp == NULL && ecode == 0) {
	report(LOG_ERR, "ckfinger: socket: %s", strerror(errno));
	return(0);
    }
    if (ecode != 0) {
	report(LOG_ERR, "ckfinger: connect %s: %s", nas, strerror(errno));
	return(0);
    }
    /* Read the finger output into a single flat buffer */
    buf = NULL;
    bufsize = 0;
    for (;;) {
	int x;

	buf = tac_realloc(buf, bufsize + incr + slop);
	x = timed_read(s, (unsigned char *)(buf + bufsize), incr, 10);
	if (x <= 0) {
	    break;
	}
	bufsize += x;
    }

    /* Done talking here */
    close(s);
    buf[bufsize] = '\0';

    if (bufsize <= 0) {
	report(LOG_ERR, "ckfinger: finger failure");
	free(buf);
	return(0);
    }
    /* skip first line in buffer */
    p = strchr(buf, '\n');
    if (p) {
	p++;
    }
    p = strchr(p, '\n');
    if (p) {
	p++;
    }
    /* Tally each time this user appears */
    for (count = 0; p && *p; p = pn) {
	int i, len, nmlen;
	char nmbuf[11];

	/* Find next line */
	pn = strchr(p, '\n');
	if (pn) {
	    ++pn;
	}
	/* Calculate line length */
	if (pn) {
	    len = pn - p;
	} else {
	    len = strlen(p);
	}

	/* Line too short -> ignore */
	if (len < 14) {
	    continue;
	}
	/* Always ignore the NAS/port we're currently trying to login on. */
	if (isdigit((int) *curport)) {
	    int thisport;

	    if (sscanf(p + 1, " %d", &thisport) == 1) {
		if ((atoi(curport) == thisport) &&
		    !strcmp(idp->NAS_name, nas)) {

		    if (debug & DEBUG_MAXSESS_FLAG) {
			report(LOG_DEBUG, "%s session on %s/%s discounted",
			       user, idp->NAS_name, idp->NAS_port);
		    }
		    continue;
		}
	    }
	}
	/* Extract username, up to 10 chars wide, starting at char 13 */
	nmlen = 0;
	name = p + 13;
	/*
	 * If this is not IOS version 11, the username MAY begin at the
	 * 15th column in the line.  So, skip up to 2 leading whitespaces.
	 */
	for (i = 0; i < 2; i++) {
	    if (! isspace((int)*name))
		break;
	}
	for (i = 0; *name && !isspace((int) *name) && (i < 10); i++) {
	    nmbuf[nmlen++] = *name++;
	}
	nmbuf[nmlen++] = '\0';

	/* If name matches, up the count */
	if (STREQ(user, nmbuf)) {
	    count++;

	    if (debug & DEBUG_MAXSESS_FLAG) {
		char c = *pn;

		*pn = '\0';
		report(LOG_DEBUG, "%s matches: %s", user, p);
		*pn = c;
	    }
	}
    }
    free(buf);
    return(count);
}

/*
 * Verify how many sessions a user has according to the wholog file.
 * Use finger to contact each NAS that wholog says has this user
 * logged on.
 */
int
countusers_by_finger(struct identity *idp)
{
    FILE *fp;
    struct peruser pu;
    int x, naddr, nsess, n;
    char **addrs;

    fp = fopen(wholog, "r+");
    if (fp == NULL) {
	return(0);
    }

    /* Count sessions */
    tac_lockfd(wholog, fileno(fp));
    nsess = 0;
    naddr = 0;
    addrs = NULL;

    while (fread(&pu, sizeof(pu), 1, fp) > 0) {
	int dup;

	/* Ignore records for everyone except this user */
	if (strcmp(pu.username, idp->username)) {
	    continue;
	}
	/* Only check a given NAS once */
	for (dup = 0, x = 0; x < naddr; ++x) {
	    if (STREQ(addrs[x], pu.NAS_name)) {
		dup = 1;
		break;
	    }
	}
	if (dup) {
	    continue;
	}
	/* Add this address to our list */
	addrs = (char **) tac_realloc((char *) addrs,
				      (naddr + 1) * sizeof(char *));
	addrs[naddr] = tac_strdup(pu.NAS_name);
	naddr += 1;

	/* Validate via finger */
	if (debug & DEBUG_MAXSESS_FLAG) {
	    report(LOG_DEBUG, "Running finger on %s for user %s/%s",
		   pu.NAS_name, idp->username, idp->NAS_port);
	}
	n = ckfinger(idp->username, pu.NAS_name, idp);

	if (debug & DEBUG_MAXSESS_FLAG) {
	    report(LOG_DEBUG, "finger reports %d active session%s for %s on %s",
		   n, (n == 1 ? "" : "s"), idp->username, pu.NAS_name);
	}
	nsess += n;
    }

    /* Clean up and return */
    fclose(fp);
    for (x = 0; x < naddr; ++x) {
	free(addrs[x]);
    }
    free(addrs);

    return(nsess);
}

/*
 * Estimate how many sessions a named user currently owns by looking in
 * the wholog file.
 */
int
countuser(struct identity *idp)
{
    FILE *fp;
    struct peruser pu;
    int nsess;

    /* Access log */
    fp = fopen(wholog, "r+");
    if (fp == NULL) {
	return(0);
    }
    /* Count sessions. Skip any session associated with the current port. */
    tac_lockfd(wholog, fileno(fp));
    nsess = 0;
    while (fread(&pu, sizeof(pu), 1, fp) > 0) {
	/* Current user */
	if (strcmp(pu.username, idp->username)) {
	    continue;
	}
	/* skip current port on current NAS */
	if (STREQ(portname(pu.NAS_port), portname(idp->NAS_port)) &&
	    STREQ(pu.NAS_name, idp->NAS_name)) {
	    continue;
	}
	nsess += 1;
    }

    /* Clean up and return */
    fclose(fp);
    return(nsess);
}
