/*
 * $Id: tac_plus.c,v 1.59 2009-07-16 23:31:26 heas Exp $
 *
 * TACACS_PLUS daemon suitable for using on Unix systems.
 *
 * October 1994, Lol Grant
 *
 * Copyright (c) 1994-1998 by Cisco systems, Inc.
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

#include "version.h"
#include "tac_plus.h"
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/wait.h>
#include <signal.h>

#ifdef LIBWRAP
# include <tcpd.h>
int allow_severity = 0;
int deny_severity = 0;
#endif

char *progname;			/* program name */
static int standalone = 1;	/* running standalone (1) or under inetd (0) */
static int initialised;		/* data structures have been allocated */
static int reinitialize;	/* schedule config reinitialization */
int sendauth_only;		/* don't respond to sendpass requests */
int debug;			/* debugging flags */
int facility = LOG_LOCAL3;	/* syslog facility */
int port;			/* port we're listening on */
int console;			/* write all syslog messages to console */
int parse_only;			/* exit after verbose parsing */
#if HAVE_PID_T
pid_t childpid;			/* child pid, global for unlink(PIDFILE) */
#else
int childpid;
#endif
int single;			/* single thread (for debugging) */
int opt_G;			/* foreground */
int opt_S;			/* enable single-connection */
int wtmpfd;			/* for wtmp file logging */
char *wtmpfile = NULL;
char *bind_address = NULL;

struct timeval started_at;

struct session session;     /* session data */

#define	PIDSZ	75
static char pidfilebuf[PIDSZ]; /* holds current name of the pidfile */

static RETSIGTYPE die(int);
static int init(void);
#if defined(REAPCHILD) && defined(REAPSIGIGN)
static RETSIGTYPE reapchild(int);
#endif
void start_session(void);
void vers(void);
void usage(void);

static RETSIGTYPE
die(int signum)
{
    report(LOG_NOTICE, "Received signal %d, shutting down", signum);
    if (childpid > 0)
	unlink(pidfilebuf);
    tac_exit(0);
}

static int
init(void)
{
    if (initialised)
	cfg_clean_config();

    report(LOG_NOTICE, "Reading config");

    if (!session.cfgfile) {
	report(LOG_ERR, "no config file specified");
	tac_exit(1);
    }

    /* read the config file */
    if (cfg_read_config(session.cfgfile)) {
	report(LOG_ERR, "Parsing %s", session.cfgfile);
	tac_exit(1);
    }

    if (session.acctfile == NULL && !(session.flags & SESS_FLAG_ACCTSYSL))
	session.acctfile = tac_strdup(TACPLUS_ACCTFILE);

    initialised++;
    reinitialize = 0;
    report(LOG_NOTICE, "Version %s Initialized %d", version, initialised);

    return 0;
}

static RETSIGTYPE
handler(int signum)
{
    report(LOG_NOTICE, "Received signal %d", signum);
    reinitialize = 1;
#ifdef REARMSIGNAL
    signal(SIGUSR1, handler);
    signal(SIGHUP, handler);
#endif
}

#if defined(REAPCHILD) && defined(REAPSIGIGN)
static
RETSIGTYPE
reapchild(int notused)
{
#ifdef UNIONWAIT
    union wait status;
#else
    int status;
#endif
#if HAVE_PID_T
    pid_t pid;
#else
    int pid;
#endif

    for (;;) {
	pid = wait3(&status, WNOHANG, 0);
	if (pid <= 0)
	    return;
	if (debug & DEBUG_FORK_FLAG)
	    report(LOG_DEBUG, "%l reaped", (long)pid);
    }
}
#endif /* REAPCHILD */

/*
 * Return a socket bound to an appropriate port number/address. Exits
 * the program on failure.
 */
int
get_socket(void)
{
    int s;
    struct sockaddr_in sin;
    struct servent *sp;
    u_long inaddr;
    int on = 1,
	kalive = 1;

    memset((char *)&sin, 0, sizeof(sin));

    if (port) {
	sin.sin_port = htons(port);
    } else {
	sp = getservbyname("tacacs", "tcp");
	if (sp)
	    sin.sin_port = sp->s_port;
	else {
	    report(LOG_ERR, "Cannot find socket port");
	    tac_exit(1);
	}
    }

    sin.sin_family = AF_INET;
    if (! bind_address) {
	sin.sin_addr.s_addr = htonl(INADDR_ANY);
    } else {
	if ((inaddr = inet_addr(bind_address)) != -1) {
	    /* A dotted decimal address */
	    memcpy(&sin.sin_addr, &inaddr, sizeof(inaddr));
	    sin.sin_family = AF_INET;
	} else {
	    report(LOG_ERR, "Invalid bind address specification: '%s'",
		bind_address);
	    tac_exit(1);
	}
    }

    s = socket(AF_INET, SOCK_STREAM, 0);

    if (s < 0) {
	console++;
	report(LOG_ERR, "get_socket: socket: %s", strerror(errno));
	tac_exit(1);
    }
#ifdef SO_REUSEADDR
    if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char *)&on, sizeof(on)) < 0)
	perror("setsockopt - SO_REUSEADDR");
#endif

    if (setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, (void *)&kalive,
		   sizeof(kalive)) < 0)
	    perror("setsockopt - SO_KEEPALIVE");
    on = 0;
    (void)setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (char *)&on, sizeof(on));
    if (bind(s, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
	console++;
	report(LOG_ERR, "get_socket: bind %d %s", ntohs(sin.sin_port),
	       strerror(errno));
	tac_exit(1);
    }
    return(s);
}

void
open_logfile(void)
{
    openlog("tac_plus", LOG_PID, facility);
    setlogmask(LOG_UPTO(LOG_DEBUG));
}

/*
 * We will eventually be called from inetd or via the rc scripts directly
 * Parse arguments and act appropiately.
 */
int
main(int argc, char **argv)
{
    extern char *optarg;
    int c;
    int s;
    FILE *fp;
    int lookup_peer = 0;

#if PROFILE
    moncontrol(0);
#endif

    if ((progname = strrchr(*argv, '/')) != NULL) {
	progname++;
    } else
	progname = *argv;

    /* initialise global session data */
    memset(&session, 0, sizeof(session));
    session.peer = tac_strdup("unknown");

    open_logfile();

#ifdef TAC_PLUS_PORT
    port = TAC_PLUS_PORT;
#endif

    if (argc <= 1) {
	usage();
	tac_exit(1);
    }

    while ((c = getopt(argc, argv, "B:C:d:hiPp:tGgvSsLl:w:u:")) != EOF)
	switch (c) {
	case 'B':		/* bind() address*/
	    bind_address = optarg;
	    break;
	case 'L':		/* lookup peer names via DNS */
	    lookup_peer++;
	    break;
	case 's':		/* don't respond to sendpass */
	    sendauth_only++;
	    break;
	case 'v':		/* print version and exit */
	    vers();
	    tac_exit(1);
	case 't':
	    console++;		/* log to console too */
	    break;
	case 'P':		/* Parse config file only */
	    parse_only++;
	    break;
	case 'G':		/* foreground */
	    opt_G++;
	    break;
	case 'g':		/* single threaded */
	    single++;
	    break;
	case 'p':		/* port */
	    port = atoi(optarg);
	    break;
	case 'd':		/* debug */
	    debug |= atoi(optarg);
	    break;
	case 'C':		/* config file name */
	    session.cfgfile = tac_strdup(optarg);
	    break;
	case 'h':		/* usage */
	    usage();
	    tac_exit(0);
	case 'i':		/* inetd mode */
	    standalone = 0;
	    break;
	case 'l':		/* logfile */
	    logfile = tac_strdup(optarg);
	    break;
	case 'S':		/* enable single-connection */
	    opt_S = 1;
	    break;
#ifdef MAXSESS
	case 'w':		/* wholog file */
	    wholog = tac_strdup(optarg);
	    break;
#endif
	case 'u':
	    wtmpfile = tac_strdup(optarg);
	    break;

	default:
	    fprintf(stderr, "%s: bad switch %c\n", progname, c);
	    usage();
	    tac_exit(1);
	}

    if (geteuid() != 0) {
	fprintf(stderr, "Warning, not running as uid 0\n");
	fprintf(stderr, "Tac_plus is usually run as root\n");
    }

    parser_init();

    /* read the configuration/etc */
    init();

    signal(SIGUSR1, handler);
    signal(SIGHUP, handler);
    signal(SIGTERM, die);
    signal(SIGPIPE, SIG_IGN);

    if (parse_only)
	tac_exit(0);

    if (debug)
	report(LOG_DEBUG, "tac_plus server %s starting", version);

    if (!standalone) {
	/* running under inetd */
	struct sockaddr_in name;
	socklen_t name_len;
#ifdef FIONBIO
	int on = 1;
#endif

	name_len = sizeof(name);
	session.flags |= SESS_NO_SINGLECONN;

	session.sock = 0;
	if (getpeername(session.sock, (struct sockaddr *)&name, &name_len)) {
	    report(LOG_ERR, "getpeername failure %s", strerror(errno));
	} else {
	    struct hostent *hp = NULL;

	    if (lookup_peer) {
		hp = gethostbyaddr((char *)&name.sin_addr.s_addr,
				   sizeof(name.sin_addr.s_addr), AF_INET);
	    }
	    if (session.peer) {
		free(session.peer);
	    }
	    session.peer = tac_strdup(hp ? hp->h_name :
				      (char *)inet_ntoa(name.sin_addr));

	    if (session.peerip)
		free(session.peerip);
	    session.peerip = tac_strdup((char *)inet_ntoa(name.sin_addr));
	    if (debug & DEBUG_AUTHEN_FLAG)
		report(LOG_INFO, "session.peerip is %s", session.peerip);
	}
#ifdef FIONBIO
	if (ioctl(session.sock, FIONBIO, &on) < 0) {
	    report(LOG_ERR, "ioctl(FIONBIO) %s", strerror(errno));
	    tac_exit(1);
	}
#endif
	start_session();
	tac_exit(0);
    }

    if (single) {
	session.flags |= SESS_NO_SINGLECONN;
    } else {
	/*
	 * Running standalone; background ourselves and release controlling
	 * tty, unless -G option was specified to keep the parent in the
	 * foreground.
	 */
#ifdef SIGTTOU
	signal(SIGTTOU, SIG_IGN);
#endif
#ifdef SIGTTIN
	signal(SIGTTIN, SIG_IGN);
#endif
#ifdef SIGTSTP
	signal(SIGTSTP, SIG_IGN);
#endif
	if (!opt_S)
	    session.flags |= SESS_NO_SINGLECONN;

	if (!opt_G) {
	    if ((childpid = fork()) < 0)
		report(LOG_ERR, "Can't fork first child");
	    else if (childpid > 0)
		exit(0);		/* parent */

	    if (debug)
		report(LOG_DEBUG, "Backgrounded");

#if SETPGRP_VOID
	    if (setpgrp() == -1)
#else
	    if (setpgrp(0, getpid()) == -1)
#endif /* SETPGRP_VOID */
		report(LOG_ERR, "Can't change process group: %s",
		       strerror(errno));

	    /* XXX What does "REAPCHILD" have to do with TIOCNOTTY? */
#ifndef REAPCHILD
	    c = open("/dev/tty", O_RDWR);
	    if (c >= 0) {
		ioctl(c, TIOCNOTTY, (char *)0);
		(void) close(c);
	    }
#else /* REAPCHILD */
	    if ((childpid = fork()) < 0)
		report(LOG_ERR, "Can't fork second child");
	    else if (childpid > 0)
		exit(0);

	    if (debug & DEBUG_FORK_FLAG)
		report(LOG_DEBUG, "Forked grandchild");

#endif /* REAPCHILD */

	    /* some systems require this */
	    closelog();

	    for (c = getdtablesize(); c >= 0; c--)
		(void)close(c);

	    /*
	     * make sure we can still log to syslog now that we have closed
	     * everything
	     */
	    open_logfile();
	}
    }
#if REAPCHILD
#if REAPSIGIGN
    signal(SIGCHLD, reapchild);
#else
    signal(SIGCHLD, SIG_IGN);
#endif
#endif

    ostream = NULL;
    /* chdir("/"); */
    umask(022);
    errno = 0;

    s = get_socket();

#ifndef SOMAXCONN
#define SOMAXCONN 5
#endif

    if (listen(s, SOMAXCONN) < 0) {
	console++;
	report(LOG_ERR, "listen: %s", strerror(errno));
	tac_exit(1);
    }

    if (port == TAC_PLUS_PORT) {
	if (bind_address == NULL) {
	    strncpy(pidfilebuf, TACPLUS_PIDFILE, PIDSZ);
	    if (pidfilebuf[PIDSZ - 1] != '\0')
		c = PIDSZ;
	    else
		c = PIDSZ - 1;
	} else
	    c = snprintf(pidfilebuf, PIDSZ, "%s.%s", TACPLUS_PIDFILE,
			 bind_address);
    } else {
	if (bind_address == NULL)
	    c = snprintf(pidfilebuf, PIDSZ, "%s.%d", TACPLUS_PIDFILE, port);
	else
	    c = snprintf(pidfilebuf, PIDSZ, "%s.%s.%d", TACPLUS_PIDFILE,
			 bind_address, port);
    }
    if (c >= PIDSZ) {
	pidfilebuf[PIDSZ - 1] = '\0';
	report(LOG_ERR, "pid filename truncated: %s", pidfilebuf);
	childpid = 0;
    } else {
	/* write process id to pidfile */
	if ((fp = fopen(pidfilebuf, "w")) != NULL) {
	    fprintf(fp, "%d\n", (int)getpid());
	    fclose(fp);
	    /*
	     * After forking to disassociate; make sure we know we're the
	     * mother so that we remove our pid file upon exit in die().
	     */
	    childpid = 1;
	} else {
	    report(LOG_ERR, "Cannot write pid to %s %s", pidfilebuf,
		   strerror(errno));
	    childpid = 0;
	}
    }
#ifdef TACPLUS_GROUPID
    if (setgid(TACPLUS_GROUPID))
	report(LOG_ERR, "Cannot set group id to %d %s",
	       TACPLUS_GROUPID, strerror(errno));
#endif

#ifdef TACPLUS_USERID
    if (setuid(TACPLUS_USERID))
	report(LOG_ERR, "Cannot set user id to %d %s",
	       TACPLUS_USERID, strerror(errno));
#endif

#ifdef MAXSESS
    maxsess_loginit();
#endif /* MAXSESS */

    report(LOG_DEBUG, "uid=%d euid=%d gid=%d egid=%d s=%d",
	   getuid(), geteuid(), getgid(), getegid(), s);

    for (;;) {
#if HAVE_PID_T
	pid_t pid;
#else
	int pid;
#endif
	struct sockaddr_in from;
	socklen_t from_len;
	struct pollfd pfds;
	int newsockfd, status;
	struct hostent *hp = NULL;

	if (reinitialize)
	    init();

	pfds.fd = s;
	pfds.events = POLLIN | POLLERR | POLLHUP | POLLNVAL;
	status = poll(&pfds, 1, TAC_PLUS_ACCEPT_TIMEOUT * 1000);
	if (status == 0)
	    continue;
	if (status == -1)
	    if (errno == EINTR)
		continue;

	memset((char *)&from, 0, sizeof(from));
	from_len = sizeof(from);
	newsockfd = accept(s, (struct sockaddr *)&from, &from_len);

	if (newsockfd < 0) {
	    if (errno == EINTR)
		continue;

	    report(LOG_ERR, "accept: %s", strerror(errno));
	    continue;
	}

	if (lookup_peer) {
	    hp = gethostbyaddr((char *)&from.sin_addr.s_addr,
			       sizeof(from.sin_addr.s_addr), AF_INET);
	}

	if (session.peer) {
	    free(session.peer);
	}
	session.peer = tac_strdup(hp ? hp->h_name :
				  (char *)inet_ntoa(from.sin_addr));

	if (session.peerip)
	    free(session.peerip);
	session.peerip = tac_strdup((char *)inet_ntoa(from.sin_addr));
	if (debug & DEBUG_AUTHEN_FLAG)
	    report(LOG_INFO, "session.peerip is %s", session.peerip);

	if (debug & DEBUG_PACKET_FLAG)
	    report(LOG_DEBUG, "session request from %s sock=%d",
		   session.peer, newsockfd);

	if (!single) {
	    pid = fork();

	    if (pid < 0) {
		report(LOG_ERR, "fork error");
		tac_exit(1);
	    }
	} else {
	    pid = 0;
	}

	if (pid == 0) {
	    /* child */
	    if (!single)
		close(s);
	    session.sock = newsockfd;
#ifdef LIBWRAP
	    if (! hosts_ctl(progname,session.peer,session.peerip,progname)) {
		report(LOG_ALERT, "refused connection from %s [%s]",
		       session.peer, session.peerip);
		shutdown(session.sock, 2);
		close(session.sock);
		if (!single) {
		    tac_exit(0);
		} else {
		    close(session.sock);
		    continue;
		}
	    }
	    if (debug) 
	      report(LOG_DEBUG, "connect from %s [%s]", session.peer,
		   session.peerip);
#endif
#if PROFILE
	    moncontrol(1);
#endif

	    start_session();
	    shutdown(session.sock, 2);
	    close(session.sock);
	    if (!single)
		tac_exit(0);
	} else {
	    if (debug & DEBUG_FORK_FLAG)
		report(LOG_DEBUG, "forked %l", (long)pid);
	    /* parent */
	    close(newsockfd);
	}
    }
}

#ifndef HAVE_GETDTABLESIZE
int
getdtablesize(void)
{
    return(_NFILE);
}
#endif /* HAVE_GETDTABLESIZE */

/* Make sure version number is kosher. Return 0 if it is */
int
bad_version_check(u_char *pak)
{
    HDR *hdr = (HDR *)pak;

    switch (hdr->type) {
    case TAC_PLUS_AUTHEN:
	/*
	 * Let authen routines take care of more sophisticated version
	 * checking as its now a bit involved.
	 */
	return(0);

    case TAC_PLUS_AUTHOR:
    case TAC_PLUS_ACCT:
	if (hdr->version != TAC_PLUS_VER_0) {
	    send_error_reply(hdr->type, "Illegal packet version");
	    return(1);
	}
	return(0);

    default:
	return(1);
    }
}

/*
 * Determine the packet type, read the rest of the packet data,
 * decrypt it and call the appropriate service routine.
 *
 */
void
start_session(void)
{
    u_char *pak;
    HDR *hdr;

    do {
	session.seq_no = 0;
	session.aborted = 0;
	session.version = 0;

	pak = read_packet();
	if (pak == NULL)
	    break;

	if (debug & DEBUG_PACKET_FLAG) {
	    report(LOG_DEBUG, "validation request from %s", session.peer);
	    dump_nas_pak(pak);
	}
	hdr = (HDR *)pak;

	session.session_id = ntohl(hdr->session_id);

	/* Do some version checking */
	if (bad_version_check(pak)) {
	    free(pak);
	    break;
	}

	switch (hdr->type) {
	case TAC_PLUS_AUTHEN:
	    authen(pak);
	    free(pak);
	    break;

	case TAC_PLUS_AUTHOR:
	    author(pak);
	    free(pak);
	    break;

	case TAC_PLUS_ACCT:
	    accounting(pak);
	    break;

	default:
	    /* Note: can't send error reply if type is unknown */
	    report(LOG_ERR, "Illegal type %d in received packet", hdr->type);
	    free(pak);
	    goto OUT;
	}
    } while (!(session.flags & SESS_NO_SINGLECONN) &&
	     session.peerflags & TAC_PLUS_SINGLE_CONNECT_FLAG);

OUT:
    if (debug & DEBUG_PACKET_FLAG)
	report(LOG_DEBUG, "%s: disconnect", session.peer);
}

void
usage(void)
{
    fprintf(stderr, "Usage: tac_plus -C <config_file> [-GghiLPstv]"
		" [-B <bind address>]"
		" [-d <debug level>]"
		" [-l <logfile>]"
		" [-p <port>]"
		" [-u <wtmpfile>]"
#ifdef MAXSESS
		" [-w <whologfile>]"
#endif
		"\n");
    fprintf(stderr, "\t-G\tstay in foreground; do not detach from the tty\n"
		"\t-g\tsingle thread mode\n"
		"\t-h\tdisplay this message\n"
		"\t-i\tinetd mode\n"
		"\t-L\tlookup peer addresses for logs\n"
		"\t-P\tparse the configuration file and exit\n"
		"\t-S\tenable single-connection\n"
		"\t-s\trefuse SENDPASS\n"
		"\t-t\talso log to /dev/console\n"
		"\t-v\tdisplay version information\n");

    return;
}

void
vers(void)
{
    fprintf(stdout, "tac_plus version %s\n", version);
#if ACLS
    fprintf(stdout, "ACLS\n");
#endif
#if AIX
    fprintf(stdout, "AIX\n");
#endif
#if ARAP_DES
    fprintf(stdout, "ARAP_DES\n");
#endif
#if BSDI
    fprintf(stdout, "BSDI\n");
#endif
#if DEBUG
    fprintf(stdout, "DEBUG\n");
#endif
#if DES_DEBUG
    fprintf(stdout, "DES_DEBUG\n");
#endif
#ifdef FIONBIO
    fprintf(stdout, "FIONBIO\n");
#endif
#if FREEBSD
    fprintf(stdout, "FREEBSD\n");
#endif
#ifndef HAVE_GETDTABLESIZE
    fprintf(stdout, "GETDTABLESIZE\n");
#endif
#if HPUX
    fprintf(stdout, "HPUX\n");
#endif
#if LIBWRAP
    fprintf(stdout, "LIBWRAP\n");
#endif
#if LINUX
    fprintf(stdout, "LINUX\n");
#endif
#if LITTLE_ENDIAN
    fprintf(stdout, "LITTLE_ENDIAN\n");
#endif
#if LOG_DAEMON
    fprintf(stdout, "LOG_DAEMON\n");
#endif
#ifdef MAXSESS
    fprintf(stdout, "MAXSESS\n");
#endif
#ifdef MAXSESS_FINGER
    fprintf(stdout, "MAXSESS_FINGER\n");
#endif
#if MIPS
    fprintf(stdout, "MIPS\n");
#endif
#if NETBSD
    fprintf(stdout, "NETBSD\n");
#endif
#ifdef HAVE_PAM
    fprintf(stdout, "PAM\n");
#endif
#ifdef NO_PWAGE
    fprintf(stdout, "NO_PWAGE\n");
#endif
#ifdef REAPCHILD
    fprintf(stdout, "REAPCHILD\n");
#endif
#ifdef REAPSIGIGN
    fprintf(stdout, "REAPSIGIGN\n");
#endif
#ifdef REARMSIGNAL
    fprintf(stdout, "REARMSIGNAL\n");
#endif
#ifdef RETSIGTYPE
#   define _RETSIGTYPE(a)	#a
    fprintf(stdout, "RETSIGTYPE %s\n", _RETSIGTYPE(RETSIGTYPE));
#endif
#ifdef SHADOW_PASSWORDS
    fprintf(stdout, "SHADOW_PASSWORDS\n");
#endif
#if SIGTSTP
    fprintf(stdout, "SIGTSTP\n");
#endif
#if SIGTTIN
    fprintf(stdout, "SIGTTIN\n");
#endif
#if SIGTTOU
    fprintf(stdout, "SIGTTOU\n");
#endif
#if SKEY
    fprintf(stdout, "SKEY\n");
#endif
#if SOLARIS
    fprintf(stdout, "SOLARIS\n");
#endif
#if SO_REUSEADDR
    fprintf(stdout, "SO_REUSEADDR\n");
#endif
#if STDLIB_MALLOC
    fprintf(stdout, "STDLIB_MALLOC\n");
#endif
#if STRCSPN
    fprintf(stdout, "STRCSPN\n");
#endif
#if HAVE_STRERROR
    fprintf(stdout, "STRERROR\n");
#else
    fprintf(stdout, "SYSERRLIST\n");
    /* XXX: fprintf(stdout,"CONST_SYSERRLIST\n"); */
#endif
#if SYSLOG_IN_SYS
    fprintf(stdout, "SYSLOG_IN_SYS\n");
#endif
#ifdef SYSV
    fprintf(stdout, "SYSV\n");
#endif
#if TACPLUS_GROUPID
    fprintf(stdout, "TACPLUS_GROUPID\n");
#endif
#if TAC_PLUS_PORT
    fprintf(stdout, "TAC_PLUS_PORT\n");
#endif
#if TACPLUS_USERID
    fprintf(stdout, "TACPLUS_USERID\n");
#endif
#if TRACE
    fprintf(stdout, "TRACE\n");
#endif
#if UENABLE
    fprintf(stdout, "UENABLE\n");
#endif
#if UNIONWAIT
    fprintf(stdout, "UNIONWAIT\n");
#endif
#if _BSD1
    fprintf(stdout, "_BSD1\n");
#endif
#if _BSD_INCLUDES
    fprintf(stdout, "_BSD_INCLUDES\n");
#endif
#if __STDC__
    fprintf(stdout, "__STDC__\n");
#endif

    return;
}
