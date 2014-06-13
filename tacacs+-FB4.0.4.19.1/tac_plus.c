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
 *
 * Facebook Fork 2014 Cooper Lees <cooper@fb.com>
*/

#include "pathsl.h"
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
volatile sig_atomic_t reinitialize;	/* schedule config reinitialization */
int sendauth_only;		/* don't respond to sendpass requests */
int debug;			/* debugging flags */
int facility = LOG_LOCAL3;	/* syslog facility */
int port = TAC_PLUS_PORT;	/* port we're listening on */
char *portstr = TAC_PLUS_PORTSTR;
int console;			/* write all syslog messages to console */
int parse_only;			/* exit after verbose parsing */
int lookup_peer;		/* look-up peer names from addresses */
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
static int get_socket(int **, int *);
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
    /* report() is not reentrant-safe */
#define RCVSIG_STR "Received signal\n"
    write(fileno(stderr), RCVSIG_STR, strlen(RCVSIG_STR));
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
	    report(LOG_DEBUG, "%ld reaped", (long)pid);
    }
}
#endif /* REAPCHILD */

/*
 * Return a socket bound to an appropriate port number/address. Exits
 * the program on failure.
 */
static int
get_socket(int **sa, int *nsa)
{
    char	host[NI_MAXHOST], serv[NI_MAXHOST];
    struct addrinfo hint, *res, *rp;
    u_long inaddr;
    int		ecode,
		flag,
		kalive = 1,
		s;

    memset(&hint, 0, sizeof(struct addrinfo));
    hint.ai_family = AF_UNSPEC;
    hint.ai_socktype = SOCK_STREAM;
    hint.ai_protocol = IPPROTO_TCP;
    hint.ai_flags = AI_PASSIVE;
#ifdef AI_ADDRCONFIG
    hint.ai_flags |= AI_ADDRCONFIG;
#endif
    if (bind_address)
	ecode = getaddrinfo(bind_address, portstr, &hint, &res);
    else
	ecode = getaddrinfo(NULL, portstr, &hint, &res);
    if (ecode != 0) {
	report(LOG_ERR, "getaddrinfo: %s\n", gai_strerror(ecode));
	    tac_exit(1);
	}

    *sa = NULL;
    *nsa = 0;
    for (rp = res; rp != NULL; rp = rp->ai_next) {
	s = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
	if (s == -1)
	    continue;

	if (1 || debug & DEBUG_PACKET_FLAG)
	    report(LOG_DEBUG, "socket FD %d AF %d", s, rp->ai_family);
	flag = 1;
	if (rp->ai_family == AF_INET6)
	    setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &flag, sizeof(flag));
#ifdef SO_REUSEADDR
	if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char *)&flag,
		       sizeof(flag)) < 0)
	perror("setsockopt - SO_REUSEADDR");
#endif
    if (setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, (void *)&kalive,
		   sizeof(kalive)) < 0)
	    perror("setsockopt - SO_KEEPALIVE");
	flag = 0;
	if (setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (char *)&flag,
		       sizeof(flag)) < 0)
	    perror("setsockopt - SO_NODELAY");

	if (bind(s, rp->ai_addr, rp->ai_addrlen) < 0) {
	    console = 1;
	    ecode = errno;
	    if (lookup_peer)
		flag = 0;
	    else
		flag = NI_NUMERICHOST | NI_NUMERICSERV;
	    if (getnameinfo(rp->ai_addr, rp->ai_addrlen, host, NI_MAXHOST,
			    serv, NI_MAXHOST, flag)) {
		strncpy(host, "unknown", NI_MAXHOST - 1);
		host[NI_MAXHOST - 1] = '\0';
		strncpy(serv, "unknown", NI_MAXHOST - 1);
		serv[NI_MAXHOST - 1] = '\0';
	    }
	    report(LOG_ERR, "get_socket: bind %s:%s %s", host, serv,
		   strerror(ecode));
	    console = 0;
	    close(s);
	    s = -1;
	    continue;
	}
	if (*sa == NULL)
	    *sa = malloc(sizeof(int) * ++(*nsa));
	else
	    *sa = realloc(*sa, sizeof(int) * ++(*nsa));
	if (*sa == NULL) {
	    report(LOG_ERR, "malloc failure: %s", strerror(errno));
	tac_exit(1);
    }
	(*sa)[*nsa - 1] = s;
    }
    freeaddrinfo(res);

    if (*nsa < 1) {
	console = 1;
	report(LOG_ERR, "get_socket: could not bind a listening socket");
	tac_exit(1);
    }
    return(0);
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
    FILE *fp;
    int	c, *s, ns;
    struct pollfd *pfds;

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


    if (argc <= 1) {
	usage();
	tac_exit(1);
    }

    while ((c = getopt(argc, argv, "B:C:d:hiPp:tGgvSsLw:u:")) != EOF)
	switch (c) {
	case 'B':		/* bind() address*/
	    bind_address = optarg;
	    break;
	case 'L':		/* lookup peer names via DNS */
	    lookup_peer = 1;
	    break;
	case 's':		/* don't respond to sendpass */
	    sendauth_only = 1;
	    break;
	case 'v':		/* print version and exit */
	    vers();
	    tac_exit(1);
	case 't':
	    console = 1;	/* log to console too */
	    break;
	case 'P':		/* Parse config file only */
	    parse_only = 1;
	    break;
	case 'G':		/* foreground */
	    opt_G = 1;
	    break;
	case 'g':		/* single threaded */
	    single = 1;
	    break;
	case 'p':		/* port */
	    port = atoi(optarg);
	    portstr = optarg;
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

    parser_init();

    /* read the configuration/etc */
    init();

    open_logfile();

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
	char host[NI_MAXHOST];
	int on;
#ifdef IPV6
	struct sockaddr_in6 name;
#else
  struct sockaddr_in name;
#endif
	socklen_t name_len;

	name_len = sizeof(name);
	session.flags |= SESS_NO_SINGLECONN;

	session.sock = 0;
#ifdef IPV6
	if (getpeername(session.sock, (struct sockaddr6 *)&name, &name_len)) {
	    report(LOG_ERR, "getpeername failure %s", strerror(errno));
#else
	if (getpeername(session.sock, (struct sockaddr *)&name, &name_len)) {
	    report(LOG_ERR, "getpeername failure %s", strerror(errno));
#endif
	} else {
	    if (lookup_peer)
		on = 0;
	    else
		on = NI_NUMERICHOST;
#ifdef IPV6
	    if (getnameinfo((struct sockaddr6 *)&name, name_len, host, 128,
			    NULL, 0, on)) {
#else
	    if (getnameinfo((struct sockaddr *)&name, name_len, host, 128,
			    NULL, 0, on)) {
#endif
		strncpy(host, "unknown", NI_MAXHOST - 1);
		host[NI_MAXHOST - 1] = '\0';
	    }
	    if (session.peer) free(session.peer);
	    session.peer = tac_strdup(host);

	    if (session.peerip) free(session.peerip);
#ifdef IPV6
	    session.peerip = tac_strdup((char *)inet_ntop(name.sin6_family,
					&name.sin6_addr, host, name_len));
#else
	    session.peerip = tac_strdup((char *)inet_ntop(name.sin_family,
					&name.sin_addr, host, name_len));
#endif
	    if (debug & DEBUG_AUTHEN_FLAG)
		report(LOG_INFO, "session.peerip is %s", session.peerip);
	}
#ifdef FIONBIO
	on = 1;
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

    get_socket(&s, &ns);

#ifndef SOMAXCONN
#define SOMAXCONN 5
#endif

    for (c = 0; c < ns; c++) {
	if (listen(s[c], SOMAXCONN) < 0) {
	    console = 1;
	report(LOG_ERR, "listen: %s", strerror(errno));
	tac_exit(1);
    }
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

    pfds = malloc(sizeof(struct pollfd) * ns);
    if (pfds == NULL) {
	report(LOG_ERR, "malloc failure: %s", strerror(errno));
	tac_exit(1);
    }
    for (c = 0; c < ns; c++) {
	pfds[c].fd = s[c];
	pfds[c].events = POLLIN | POLLERR | POLLHUP | POLLNVAL;
    }

    for (;;) {
#if HAVE_PID_T
	pid_t pid;
#else
	int pid;
#endif
	char host[NI_MAXHOST];
#ifdef IPV6
	struct sockaddr_in6 from;
#else
	struct sockaddr_in from;
#endif
	socklen_t from_len;
	int newsockfd, status;
	int flags;

	if (reinitialize)
	    init();

	status = poll(pfds, ns, TAC_PLUS_ACCEPT_TIMEOUT * 1000);
	if (status == 0)
	    continue;
	if (status == -1)
	    if (errno == EINTR)
		continue;

	from_len = sizeof(from);
	memset((char *)&from, 0, from_len);
	for (c = 0; c < ns; c++) {
	    if (pfds[c].revents & POLLIN)
  #ifdef IPV6
		newsockfd = accept(s[c], (struct sockaddr_in6 *)&from, &from_len);
  #else
		newsockfd = accept(s[c], (struct sockaddr_in *)&from, &from_len);
  #endif
	    else if (pfds[c].revents & (POLLERR | POLLHUP | POLLNVAL)) {
		report(LOG_ERR, "exception on listen FD %d", s[c]);
		tac_exit(1);
	    }
	}

	if (newsockfd < 0) {
	    if (errno == EINTR)
		continue;

	    report(LOG_ERR, "accept: %s", strerror(errno));
	    continue;
	}

	if (lookup_peer)
	    flags = 0;
	else
	    flags = NI_NUMERICHOST;
#ifdef IPV6
	if (getnameinfo((struct sockaddr_in6 *)&from, from_len, host, 128, NULL, 0,
			flags)) {
#else
	if (getnameinfo((struct sockaddr_in *)&from, from_len, host, 128, NULL, 0,
			flags)) {
#endif
	    strncpy(host, "unknown", NI_MAXHOST - 1);
	    host[NI_MAXHOST - 1] = '\0';
	}

	if (session.peer) free(session.peer);
	session.peer = tac_strdup(host);

	if (session.peerip) free(session.peerip);
#ifdef IPV6
	session.peerip = tac_strdup((char *)inet_ntop(from.sin6_family,
          &from.sin6_addr, host, INET6_ADDRSTRLEN));
#else
	session.peerip = tac_strdup((char *)inet_ntop(from.sin_family,
          &from.sin_addr, host, INET_ADDRSTRLEN));
#endif
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
	  if (!single) {
            if (ns > 1) {
              for (c = 0; c < ns; c++) {
                close(s[c]);
              }
            }
          }
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
      report(LOG_DEBUG, "connect from %s [%s]", session.peer, session.peerip);
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
		report(LOG_DEBUG, "forked %ld", (long)pid);
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
	    free(pak);
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
#if ACECLNT
    fprintf(stdout, "ACECLNT\n");
#endif
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
