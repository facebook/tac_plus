/*
 * $Id: programs.c,v 1.13 2009-06-02 18:08:00 heas Exp $
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

/* Routines to fork children and communicate with them via pipes */

#include "tac_plus.h"
#include <sys/wait.h>
#ifdef HAVE_CTYPE_H
# include <ctype.h>
#endif
#include <unistd.h>
#include <signal.h>

static void close_fds(int, int, int);
static char *lookup(char *, struct author_data *);
#if HAVE_PID_T
static pid_t my_popen(char *, int *, int *, int *);
#else
static int my_popen(char *, int *, int *, int *);
#endif
static char **read_args(int, int);
static int read_string(int, char *, int);
static char *substitute(char *, struct author_data *);
#if HAVE_PID_T
static int waitfor(pid_t);
#else
static int waitfor(int);
#endif
static int write_args(int, char **, int);

/*
 * Support for dollar variables.  Look in the authorization data and return
 * strings representing values found there.  If not found, return "unknown".
 * Recognized strings and their interpolated value types are:
 *
 * user    -- user name
 * name    -- NAS name
 * port    -- NAS port
 * ip      -- NAS ip
 * address -- NAC address (remote user location)
 * priv    -- privilege level (0 to 15)
 * method  -- (1 to 4)
 * type    -- (1 to 4)
 * service -- (1 to 7)
 * status  -- (pass, fail, error, unknown)
 */
static char *
lookup(char *sym, struct author_data *data)
{
    static char buf[5];

    if (STREQ(sym, "user")) {
	return(tac_strdup(data->id->username));
    }
    if (STREQ(sym, "name")) {
	return(tac_strdup(data->id->NAS_name));
    }
    if (STREQ(sym, "ip")) {
	return(tac_strdup(data->id->NAS_ip));
    }
    if (STREQ(sym, "port")) {
	return(tac_strdup(data->id->NAS_port));
    }
    if (STREQ(sym, "address")) {
	return(tac_strdup(data->id->NAC_address));
    }
    if (STREQ(sym, "priv")) {
	snprintf(buf, sizeof(buf), "%d", data->id->priv_lvl);
	return(tac_strdup(buf));
    }
    if (STREQ(sym, "method")) {
	snprintf(buf, sizeof(buf), "%d", data->authen_method);
	return(tac_strdup(buf));
    }
    if (STREQ(sym, "type")) {
	snprintf(buf, sizeof(buf), "%d", data->authen_type);
	return(tac_strdup(buf));
    }
    if (STREQ(sym, "service")) {
	snprintf(buf, sizeof(buf), "%d", data->service);
	return(tac_strdup(buf));
    }
    if (STREQ(sym, "status")) {
	switch (data->status) {
	default:
	    return(tac_strdup("unknown"));
	case AUTHOR_STATUS_PASS_ADD:
	case AUTHOR_STATUS_PASS_REPL:
	    return(tac_strdup("pass"));
	case AUTHOR_STATUS_FAIL:
	    return(tac_strdup("fail"));
	case AUTHOR_STATUS_ERROR:
	    return(tac_strdup("error"));
	}
    }

    return(tac_strdup("unknown"));
}

/*
 * Interpolate values of dollar variables into a string.  Determine values
 * for the various $ variables by looking in the authorization data.
 */
static char *
substitute(char *string, struct author_data *data)
{
    char *cp;
    char out[MAX_INPUT_LINE_LEN], *outp;
    char sym[MAX_INPUT_LINE_LEN], *symp;
    char *value, *valuep;

    if (debug & DEBUG_AUTHOR_FLAG)
	report(LOG_DEBUG, "substitute: %s", string);

    cp = string;
    outp = out;

    while (*cp) {
	if (*cp != DOLLARSIGN) {
	    *outp++ = *cp++;
	    continue;
	}
	cp++;			/* skip dollar sign */
	symp = sym;

	/* does it have curly braces e.g. ${foo} ? */
	if (*cp == '{') {
	    cp++;		/* skip { */
	    while (*cp && *cp != '}')
		*symp++ = *cp++;
	    cp++;		/* skip } */

	} else {
	    /* copy symbol into sym */
	    while (*cp && isalpha((int) *cp))
		*symp++ = *cp++;
	}

	*symp = '\0';
	/* lookup value */

	if (debug & DEBUG_SUBST_FLAG)
	    report(LOG_DEBUG, "Lookup %s", sym);

	valuep = value = lookup(sym, data);

	if (debug & DEBUG_SUBST_FLAG)
	    report(LOG_DEBUG, "Expands to: %s", value);

	/* copy value into output */
	while (valuep && *valuep)
	    *outp++ = *valuep++;
	free(value);
    }
    *outp++ = '\0';

    if (debug & DEBUG_AUTHOR_FLAG)
	report(LOG_DEBUG, "Dollar substitution: %s", out);

    return(tac_strdup(out));
}

/*
 * Wait for a (child) pid to terminate.  Return its status.  Probably
 * horribly implementation dependent.
 */
static int
#if HAVE_PID_T
waitfor(pid_t pid)
#else
waitfor(int pid)
#endif
{
#if HAVE_PID_T
    pid_t ret;
#else
    int ret;
#endif

#ifdef UNIONWAIT
    union wait status;
#else
    int status;
#endif

    ret = waitpid(pid, &status, 0);

    if (ret < 0) {
	report(LOG_ERR, "%s: pid %ld no child exists", session.peer, (long)pid);
	return(-1);
    }
    if (!WIFEXITED(status)) {
	report(LOG_ERR, "%s: pid %ld child in illegal state", session.peer,
	       (long)pid);
	return(-1);
    }
    if (debug & DEBUG_AUTHOR_FLAG)
	report(LOG_DEBUG, "pid %ld child exited status %ld", (long)pid,
	       (long)WEXITSTATUS(status));

    return(WEXITSTATUS(status));
}

/* Write an argv array of strings to fd, adding a newline to each one */
static int
write_args(int fd, char **args, int arg_cnt)
{
    int i, m, n, o;

    for (i = 0; i < arg_cnt; i++) {
	n = strlen(args[i]);

	for (m = 0; m < n; ) {
	    if ((o = write(fd, args[i], n)) == -1) {
		if (errno != EINTR) {
		    report(LOG_ERR, "%s: Process write failure: %s",
			   session.peer, strerror(errno));
		    return(-1);
		}
	    } else
		m += o;
	}
	while ((m = write(fd, "\n", 1)) != 1) {
	    if (m == -1 && errno != EINTR) {
		report(LOG_ERR, "%s: Process write failure: %s", session.peer,
		       strerror(errno));
		return(-1);
	    }
	}
    }
    return(0);
}

/* Close the three given file-descruptors */
static void
close_fds(int fd1, int fd2, int fd3)
{
    if (fd1 >= 0) {
	close(fd1);
    }
    if (fd2 >= 0) {
	close(fd2);
    }
    if (fd3 >= 0) {
	close(fd3);
    }

    return;
}

/*
 * Fork a command.  Return read and write file descriptors in readfdp and
 * writefdp.  Return the pid or -1 if unsuccessful
 */
#if HAVE_PID_T
static pid_t
#else
static int
#endif
my_popen(char *cmd, int *readfdp, int *writefdp, int *errorfdp)
{
    int fd1[2], fd2[2], fd3[2];
#if HAVE_PID_T
    pid_t pid;
#else
    int pid;
#endif

    fd1[0] = fd1[1] = fd2[0] = fd2[1] = fd3[0] = fd3[1] = -1;
    *readfdp = *writefdp = *errorfdp = -1;

    if (pipe(fd1) < 0 || pipe(fd2) < 0 || pipe(fd3) < 0) {
	report(LOG_ERR, "%s: Cannot create pipes", session.peer);
	close_fds(fd1[0], fd2[0], fd3[0]);
	close_fds(fd1[1], fd2[1], fd3[1]);
	return(-1);
    }

    /* The parent who forked us is set to reap all children
       automatically. We disable this so we can explicitly reap our
       children to read their status */

    signal(SIGCHLD, SIG_DFL);

    pid = fork();

    if (pid < 0) {
	report(LOG_ERR, "%s: fork failure", session.peer);
	close_fds(fd1[0], fd2[0], fd3[0]);
	close_fds(fd1[1], fd2[1], fd3[1]);
	return(-1);
    }
    if (pid > 0) {
	/* parent */
	close_fds(fd1[0], fd2[1], fd3[1]);

	*writefdp = fd1[1];
	*readfdp = fd2[0];
	*errorfdp = fd3[0];

	return(pid);
    }
    /* child */
    closelog();
    close(session.sock);
    close_fds(fd1[1], fd2[0], fd3[0]);

    if (fd1[0] != STDIN_FILENO) {
	if (dup2(fd1[0], STDIN_FILENO) < 0)
	    exit(-1);
	close(fd1[0]);
    }
    if (fd2[1] != STDOUT_FILENO) {
	if (dup2(fd2[1], STDOUT_FILENO) < 0)
	    exit(-1);
	close(fd2[1]);
    }
    if (fd3[1] != STDERR_FILENO) {
	if (dup2(fd3[1], STDERR_FILENO) < 0)
	    exit(-1);
	close(fd3[1]);
    }
    (void) execl("/bin/sh", "sh", "-c", cmd, (char *) NULL);
    _exit(-1);

    return(0); /* keep Codecenter quiet */
}

/*
 * read the file descriptor and stuff the data into the given array for the
 * number of bytes given.  Throw the rest away.
 */
static int
read_string(int fd, char *string, int len)
{
    uint i, ret;
    char c;

    i = 0;
    do {
	ret = read(fd, &c, 1);
	if (ret > 0 && (i + 1) < len) {
	    string[i++] = c;
	    string[i] = '\0';
	}
    } while (i < len && ret > 0);
    return(ret);
}

/*
 * Read lines from fd and place them into an argv style array. Highly
 * recursive so we do not have to count lines in advance.  Uses "n" as the
 * count of lines seen so far.  When eof is read, the array is allocated,
 * and the recursion unravels
 */
static char **
read_args(int n, int fd)
{
    char buf[255], *bufp, c, **out;

    bufp = buf;

    while (read(fd, &c, 1) > 0) {
	if (c != '\n') {
	    *bufp++ = c;
	    continue;
	}
	*bufp = '\0';
	out = read_args(n + 1, fd);
	out[n] = (char *) tac_malloc(strlen(buf) + 1);
	strcpy(out[n], buf);
	return(out);
    }
    /* eof */
    out = (char **) tac_malloc(sizeof(char *) * (n + 1));
    out[n] = NULL;

    return(out);
}

/*
 * Do variable interpolation on a string, then invoke it as a shell command.
 * Write an appropriate set of AV pairs to standard input of the command and
 * read its standard output into outarray.  Return the commands final status
 * when it terminates
 */
int
call_pre_process(char *string, struct author_data *data, char ***outargsp,
		 int *outargs_cntp, char *error, int err_len)
{
    char **new_args;
    int readfd, writefd, errorfd;
    int status, i;
    char *cmd = substitute(string, data);
#if HAVE_PID_T
    pid_t pid;
#else
    int pid;
#endif

    pid = my_popen(cmd, &readfd, &writefd, &errorfd);
    memset(error, '\0', err_len);

    free(cmd);

    if (pid < 0) {
	close_fds(readfd, writefd, errorfd);
	return(1);		/* deny */
    }

    for (i = 0; i < data->num_in_args; i++) {
	if (debug & DEBUG_AUTHOR_FLAG)
	    report(LOG_DEBUG, "input %s", data->input_args[i]);
    }

    if (write_args(writefd, data->input_args, data->num_in_args)) {
	close_fds(readfd, writefd, errorfd);
	return(1);		/* deny */
    }

    close(writefd);
    writefd = -1;

    new_args = read_args(0, readfd);
    *outargsp = new_args;

    if (debug & DEBUG_AUTHOR_FLAG) {
	for (i = 0; new_args[i]; i++) {
	    report(LOG_DEBUG, "output %s", new_args[i]);
	}
    }

    read_string(errorfd, error, err_len);
    if (error[0] != '\0') {
	report(LOG_ERR, "Error from program (%d): \"%s\" ",
	       strlen(error), error);
    }

    /* count the args */
    for (i = 0; new_args[i]; i++)
	 /* NULL stmt */ ;

    *outargs_cntp = i;

    status = waitfor(pid);
    close_fds(readfd, writefd, errorfd);
    return(status);
}

/*
 * Do variable interpolation on a string, then invoke it as a shell command.
 * Write an appropriate set of AV pairs to standard input of the command and
 * read its standard output into outarray.  Return the commands final status
 * when it terminates
 */
int
call_post_process(char *string, struct author_data *data, char ***outargsp,
		  int *outargs_cntp)
{
    char **new_args;
    int status;
    int readfd, writefd, errorfd;
    int i;
    char *cmd = substitute(string, data);
#if HAVE_PID_T
    pid_t pid;
#else
    int pid;
#endif

    pid = my_popen(cmd, &readfd, &writefd, &errorfd);
    free(cmd);

    if (pid < 0) {
	close_fds(readfd, writefd, errorfd);
	return(1);		/* deny */
    }

    /* If the status is AUTHOR_STATUS_PASS_ADD then the current output args
     * represent *additions* to the input args, not the full set */

    if (data->status == AUTHOR_STATUS_PASS_ADD) {

	for (i = 0; i < data->num_in_args; i++) {
	    if (debug & DEBUG_AUTHOR_FLAG)
		report(LOG_DEBUG, "input %s", data->input_args[i]);
	}

	if (write_args(writefd, data->input_args, data->num_in_args)) {
	    close_fds(readfd, writefd, errorfd);
	    return(1);		/* deny */
	}
    }
    for (i = 0; i < data->num_out_args; i++) {
	if (debug & DEBUG_AUTHOR_FLAG)
	    report(LOG_DEBUG, "input %s", data->output_args[i]);
    }

    if (write_args(writefd, data->output_args, data->num_out_args)) {
	close_fds(readfd, writefd, errorfd);
	return(1);		/* deny */
    }

    close(writefd);
    writefd = -1;

    new_args = read_args(0, readfd);
    *outargsp = new_args;

    if (debug & DEBUG_AUTHOR_FLAG) {
	for (i = 0; new_args[i]; i++) {
	    report(LOG_DEBUG, "output %s", new_args[i]);
	}
    }
    /* count the output args */
    for (i = 0; new_args[i]; i++)
	 /* NULL stmt */ ;

    *outargs_cntp = i;

    status = waitfor(pid);
    close_fds(readfd, writefd, errorfd);

    return(status);
}
