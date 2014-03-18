/*
 * $Id: tac_plus.h,v 1.55 2009/07/17 16:10:52 heas Exp $
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

#include "config.h"

/*
 * If you are defining a system from scratch, the following may be useful.
 * Otherwise, just use the system definitions below this section.
 */

/* Define this for minor include file differences on SYSV-based systems */
/* #define SYSV */

/* use strerror() if we have one, else sys_errlist[errno] */
#ifndef HAVE_STRERROR
# define strerror(a)	sys_errlist[a]
#endif

/* Define this if your password file does not contain age and comment fields. */
#define NO_PWAGE

/*
 * Define this if you have DES routines you can link to for ARAP (See the
 * user guide for more details).
 */
/* #define ARAP_DES */

/* System definitions. */
#ifdef AIX
/*
 * The only way to properly compile BSD stuff on AIX is to define a
 * "bsdcc" compiler on your system.  See /usr/lpp/bos/bsdport on your
 * system for details. People who do NOT do this tell me that the code
 * still compiles but that it then doesn't behave correctly e.g. child
 * processes are not reaped correctly.  Don't expect much sympathy if
 * you do this.
 */
#define _BSD 1
#define _BSD_INCLUDES
#define NO_PWAGE
#endif /* AIX */

#if LINUX
#define NO_PWAGE
#include <unistd.h>
#ifdef GLIBC
#define CONST_SYSERRLIST
#endif
#endif /* LINUX */

#ifdef MIPS
#define SYSV
#endif /* MIPS */

#ifdef NETBSD
#define NO_PWAGE
#define CONST_SYSERRLIST
#endif

#ifdef SOLARIS
#define SYSV
#endif /* SOLARIS */

#ifdef HPUX
#define SYSV
#endif /* HPUX */

#ifdef FREEBSD
#define CONST_SYSERRLIST
#define NO_PWAGE
#endif

#ifdef BSDI
#define NO_PWAGE
#endif

#define MD5_LEN           16
#ifdef MSCHAP
#define MSCHAP_DIGEST_LEN 49
#endif /* MSCHAP */

#if HAVE_STRING_H
# include <string.h>
#endif
#if HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
#include <errno.h>
#include <netdb.h>
#include <pwd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/file.h>
#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

#if HAVE_MALLOC_H
# include <malloc.h>
#endif

#if HAVE_STDLIB_H
# include <stdlib.h>
#endif

#if HAVE_SYSLOG_H
# include <syslog.h>
#else
# include <sys/syslog.h>
#endif

#include <utmp.h>

#include <unistd.h>

#if HAVE_STRINGS_H
# include <strings.h>
#endif
#if HAVE_FCNTL_H
# include <fcntl.h>
#endif

#include "tacacs.h"
#include "pathsl.h"
#include "md5.h"

/*
 * You probably shouldn't be changing much below this line unless you really
 * know what you are doing.
 */

#define DOLLARSIGN '$'

/*
 * XTACACSP protocol defintions
 */

/*
 * This structure describes an authentication method.
 *   authen_name     contains the name of the authentication method.
 *   authen_func     is a pointer to the authentication function.
 *   authen_method   numeric value of authentication method
 */

#define AUTHEN_NAME_SIZE 128

struct authen_type {
    char authen_name[AUTHEN_NAME_SIZE];
    int (*authen_func)();
    int authen_type;
};

/* This structure describes a principal that is to be authenticated. */
struct identity {
    char *username;		/* principals name (ASCII, null terminated) */
    char *NAS_name;		/* name of the NAS where the user is */
    char *NAS_port;		/* port on the NAS where the user is */
    char *NAS_ip;		/* IP address of the NAS */
    char *NAC_address;		/* remote user location. This may be a remote
				 * IP address or a caller-ID or ...
				 */
    int priv_lvl;		/* user's requested privilege level */
};

/*
 * The authen_data structure is the data structure for passing
 * information to and from the authentication function
 * (authen_type.authen_func).
 */
struct authen_data {
    struct identity *NAS_id;	/* user identity */
    char *server_msg;		/* null-terminated output msg */

    int server_dlen;		/* output data length */
    char *server_data;		/* output data */

    char *client_msg;		/* null-terminated input msg a user typed */

    int client_dlen;		/* input data length */
    char *client_data;		/* input data */

    void *method_data;		/* opaque private method data */
    int action;			/* what's to be done */
    int service;		/* calling service */
    int status;			/* Authen status */
    int type;			/* Authen type */
    u_char flags;               /* input & output flags fields */
};

/* return values for  choose_authen(); */
#define CHOOSE_FAILED -1     /* failed to choose an authentication function */
#define CHOOSE_OK      0     /* successfully chose an authentication function */
#define CHOOSE_GETUSER 1     /* need a username before choosing */
#define CHOOSE_BADTYPE 2     /* Invalid preferred authen function specified */

/*
 * This structure is the data structure for passing information to
 * and from the authorization function (do_author()).
 */
struct author_data {
    struct identity *id;	/* user id */
    int authen_method;		/* authentication method */
#define AUTHEN_METH_NONE             0x01
#define AUTHEN_METH_KRB5             0x02
#define AUTHEN_METH_LINE             0x03
#define AUTHEN_METH_ENABLE           0x04
#define AUTHEN_METH_LOCAL            0x05
#define AUTHEN_METH_TACACSPLUS       0x06
#define AUTHEN_METH_RCMD             0x20

    int authen_type;		/* authentication type see authen_type */
    int service;		/* calling service */
    char *msg;		        /* optional NULL-terminated return message */
    char *admin_msg;	        /* optional NULL-terminated admin message */
    int status;			/* return status */
#define AUTHOR_STATUS_PASS_ADD       0x01
#define AUTHOR_STATUS_PASS_REPL      0x02
#define AUTHOR_STATUS_FAIL           0x10
#define AUTHOR_STATUS_ERROR          0x11

    int num_in_args;		/* input arg count */
    char **input_args;		/* input arguments */
    int num_out_args;		/* output arg cnt */
    char **output_args;		/* output arguments */
};

/* An API accounting record structure */
struct acct_rec {
    int acct_type;		/* start, stop, update */
#define ACCT_TYPE_START      1
#define ACCT_TYPE_STOP       2
#define ACCT_TYPE_UPDATE     3

    struct identity *identity;
    int authen_method;
    int authen_type;
    int authen_service;
    char *msg;       /* output field */
    char *admin_msg; /* output field */
    int num_args;
    char **args;
};

#define NAS_PORT_MAX_LEN                255

struct session {
    int session_id;                /* host specific unique session id */
    int aborted;                   /* have we received an abort flag? */
    int seq_no;                    /* seq. no. of last packet exchanged */
    time_t last_exch;              /* time of last packet exchange */
    int sock;                      /* socket for this connection */
    int flags;
#define SESS_FLAG_ACCTSYSL	0x1		/* syslog accounting records */
#define SESS_NO_SINGLECONN	0x2		/* single-connect not allowed*/
    int peerflags;		   /* header flags from client */
    char *key;                     /* the key */
    int keyline;                   /* line number key was found on */
    char *peer;                    /* name of connected peer */
    char *peerip;                  /* ip of connected peer */
    char *cfgfile;                 /* config file name */
    char *acctfile;                /* name of accounting file */
    char port[NAS_PORT_MAX_LEN+1]; /* For error reporting */
    u_char version;                /* version of last packet read */
};

extern struct session session;     /* the session */

/* Global variables */
extern int console;                /* log to console */
extern int debug;                  /* debugging flag */
extern int facility;		   /* syslog facility */
extern char *logfile;
extern FILE *ostream;              /* for logging to console */
extern int parse_only;             /* exit after parsing verbosely */
extern int sendauth_only;          /* don't do sendauth */
extern int single;                 /* do not fork (for debugging) */
extern struct timeval started_at;
extern char *wtmpfile;
extern int wtmpfd;

#define HASH_TAB_SIZE 157        /* user and group hash table sizes */

typedef struct tac_plus_pak_hdr HDR;

/* Authentication packet NAS sends to us */
struct authen_start {
    u_char action;
#define TAC_PLUS_AUTHEN_LOGIN    0x1
#define TAC_PLUS_AUTHEN_CHPASS   0x2
#define TAC_PLUS_AUTHEN_SENDPASS 0x3 /* deprecated */
#define TAC_PLUS_AUTHEN_SENDAUTH 0x4

    u_char priv_lvl;
#define TAC_PLUS_PRIV_LVL_MIN 0x0
#define TAC_PLUS_PRIV_LVL_MAX 0xf

    u_char authen_type;
#define TAC_PLUS_AUTHEN_TYPE_ASCII  1
#define TAC_PLUS_AUTHEN_TYPE_PAP    2
#define TAC_PLUS_AUTHEN_TYPE_CHAP   3
#define TAC_PLUS_AUTHEN_TYPE_ARAP   4
#ifdef MSCHAP
#define TAC_PLUS_AUTHEN_TYPE_MSCHAP 5
#endif /* MSCHAP */

    u_char service;
#define TAC_PLUS_AUTHEN_SVC_LOGIN  1
#define TAC_PLUS_AUTHEN_SVC_ENABLE 2
#define TAC_PLUS_AUTHEN_SVC_PPP    3
#define TAC_PLUS_AUTHEN_SVC_ARAP   4
#define TAC_PLUS_AUTHEN_SVC_PT     5
#define TAC_PLUS_AUTHEN_SVC_RCMD   6
#define TAC_PLUS_AUTHEN_SVC_X25    7
#define TAC_PLUS_AUTHEN_SVC_NASI   8

    u_char user_len;				/* bytes of char data */
    u_char port_len;				/* bytes of char data */
    u_char rem_addr_len;			/* bytes of u_char data */
    u_char data_len;				/* bytes of u_char data */
};

#define TAC_AUTHEN_START_FIXED_FIELDS_SIZE 8

/* Authentication continue packet NAS sends to us */
struct authen_cont {
    u_short user_msg_len;
    u_short user_data_len;
    u_char flags;
#define TAC_PLUS_CONTINUE_FLAG_ABORT 0x1

    /* <user_msg_len bytes of u_char data> */
    /* <user_data_len bytes of u_char data> */
};

#define TAC_AUTHEN_CONT_FIXED_FIELDS_SIZE 5

/* Authentication reply packet we send to NAS */
struct authen_reply {
    u_char status;
#define TAC_PLUS_AUTHEN_STATUS_PASS     1
#define TAC_PLUS_AUTHEN_STATUS_FAIL     2
#define TAC_PLUS_AUTHEN_STATUS_GETDATA  3
#define TAC_PLUS_AUTHEN_STATUS_GETUSER  4
#define TAC_PLUS_AUTHEN_STATUS_GETPASS  5
#define TAC_PLUS_AUTHEN_STATUS_RESTART  6
#define TAC_PLUS_AUTHEN_STATUS_ERROR    7
#define TAC_PLUS_AUTHEN_STATUS_FOLLOW   0x21

    u_char flags;
#define TAC_PLUS_AUTHEN_FLAG_NOECHO     0x1

    u_short msg_len;
    u_short data_len;

    /* <msg_len bytes of char data> */
    /* <data_len bytes of u_char data> */
};

#define TAC_AUTHEN_REPLY_FIXED_FIELDS_SIZE 6

/* An authorization request packet */
struct author {
    u_char authen_method;
    u_char priv_lvl;
    u_char authen_type;
    u_char service;

    u_char user_len;				/* bytes of char data */
    u_char port_len;				/* bytes of char data */
    u_char rem_addr_len;			/* bytes of u_char data */
    u_char arg_cnt;				/* the number of args */

    /* <arg_cnt u_chars containing the lengths of args 1 to arg n> */
    /* <char data for each arg> */
};

#define TAC_AUTHOR_REQ_FIXED_FIELDS_SIZE 8

/* An authorization reply packet */
struct author_reply {
    u_char status;
    u_char arg_cnt;
    u_short msg_len;
    u_short data_len;

    /* <arg_cnt u_chars containing the lengths of arg 1 to arg n> */
    /* <msg_len bytes of char data> */
    /* <data_len bytes of char data> */
    /* <char data for each arg> */
};

#define TAC_AUTHOR_REPLY_FIXED_FIELDS_SIZE 6

struct acct {
    u_char flags;
#define TAC_PLUS_ACCT_FLAG_MORE     0x1
#define TAC_PLUS_ACCT_FLAG_START    0x2
#define TAC_PLUS_ACCT_FLAG_STOP     0x4
#define TAC_PLUS_ACCT_FLAG_WATCHDOG 0x8

    u_char authen_method;
    u_char priv_lvl;
    u_char authen_type;
    u_char authen_service;
    u_char user_len;				/* bytes of char data */
    u_char port_len;				/* bytes of char data */
    u_char rem_addr_len;			/* bytes of u_char data */
    u_char arg_cnt; /* the number of cmd args */
    /* one u_char containing size for each arg */
    /* char data for args 1 ... n */
};

#define TAC_ACCT_REQ_FIXED_FIELDS_SIZE 9

struct acct_reply {
    u_short msg_len;
    u_short data_len;
    u_char status;
#define TAC_PLUS_ACCT_STATUS_SUCCESS 0x1
#define TAC_PLUS_ACCT_STATUS_ERROR   0x2
#define TAC_PLUS_ACCT_STATUS_FOLLOW  0x21
};

#define TAC_ACCT_REPLY_FIXED_FIELDS_SIZE 5

/* Odds and ends */
#define TAC_PLUS_MAX_ITERATIONS 50
#undef MIN
#define MIN(a,b) ((a)<(b)?(a):(b))
#define STREQ(a,b) (strcmp(a,b)==0)
#define MAX_INPUT_LINE_LEN 255

/* Debugging flags */

#define DEBUG_PARSE_FLAG     2
#define DEBUG_FORK_FLAG      4
#define DEBUG_AUTHOR_FLAG    8
#define DEBUG_AUTHEN_FLAG    16
#define DEBUG_PASSWD_FLAG    32
#define DEBUG_ACCT_FLAG      64
#define DEBUG_CONFIG_FLAG    128
#define DEBUG_PACKET_FLAG    256
#define DEBUG_HEX_FLAG       512
#define DEBUG_MD5_HASH_FLAG  1024
#define DEBUG_XOR_FLAG       2048
#define DEBUG_CLEAN_FLAG     4096
#define DEBUG_SUBST_FLAG     8192
#define DEBUG_PROXY_FLAG     16384
#define DEBUG_MAXSESS_FLAG   32768
#define DEBUG_LOCK_FLAG      65536

#define TAC_IS_USER           1
#define TAC_PLUS_RECURSE      1
#define TAC_PLUS_NORECURSE    0

#define DEFAULT_USERNAME "DEFAULT"

#include "parse.h"

/* Node types */

#define N_arg           50
#define N_optarg        51
#define N_svc_exec      52
#define N_svc_slip      53
#define N_svc_ppp       54
#define N_svc_arap      55
#define N_svc_cmd       56
#define N_permit        57
#define N_deny          58
#define N_svc           59

/* A parse tree node */
struct node {
    int type;     /* node type (arg, svc, proto) */
    void *next;   /* pointer to next node in chain */
    void *value;  /* node value */
    void *value1; /* node value */
    int dflt;     /* default value for node */
    int line;     /* line number declared on */
};
typedef struct node NODE;

union v {
    int intval;
    void *pval;
};
typedef union v VALUE;

/* acct.c */
void accounting(u_char *);

/* authen.c */
void authen(u_char *);

/* author.c */
void author(u_char *);

/* choose_authen.c */
int choose_authen(struct authen_data *, struct authen_type *);

/* report.c */
void report_string(int, u_char *, int);
void report_hex(int, u_char *, int);
#ifdef __STDC__
void report(int priority, char *fmt, ...);
#else
void report();
#endif

/* utils.c */
RETSIGTYPE tac_exit(int);
int tac_lockfd(char *, int);
char *tac_malloc(int);
char *tac_strdup(char *);
char *tac_make_string(u_char *, int);
char *tac_find_substring(char *, char *);
char *tac_realloc(char *, int);

/* do_acct.c */
int do_acct_file(struct acct_rec *);
int do_acct_syslog(struct acct_rec *);
int do_wtmp(struct acct_rec *);

/* do_author.c */
int do_author(struct author_data *);

/* dump.c */
void dump_header(u_char *);
void dump_nas_pak(u_char *);
void dump_tacacs_pak(u_char *);
char *summarise_outgoing_packet_type(u_char *);
char *summarise_incoming_packet_type(u_char *);

/* hash.c */
struct entry;
void *hash_add_entry(void **, struct entry *);
void **hash_get_entries(void **);
void *hash_lookup(void **, char *);

/* config.c */
#ifdef ACLS
int	cfg_acl_check(char *, char *);
#endif
void	cfg_clean_config(void);
char	*cfg_get_arap_secret(char *, int);
char	*cfg_get_authen_default(void);
char	*cfg_get_chap_secret(char *, int);
NODE	*cfg_get_cmd_node(char *, char *, int);
#ifdef UENABLE
char	*cfg_get_enable_secret(char *, int);
int	cfg_get_user_noenablepwd(char *, int);
#endif
char	*cfg_get_expires(char *, int);
int	cfg_get_intvalue(char *, int, int, int);
char	*cfg_get_phvalue(char *, int);
char	*cfg_get_pvalue(char *, int, int, int);
char	*cfg_get_global_secret(char *, int);
char	*cfg_get_host_enable(char *);
char	*cfg_get_host_key(char *);
#ifdef UENABLE
int	cfg_get_host_noenablepwd(char *);
#endif
char	*cfg_get_host_prompt(char *);
char	*cfg_get_login_secret(char *, int);
#ifdef MSCHAP
char	*cfg_get_mschap_secret(char *, int);
#endif
char	*cfg_get_opap_secret(char *, int);
char	*cfg_get_pap_secret(char *, int);
char	**cfg_get_svc_attrs(NODE *, int *);
NODE	*cfg_get_svc_node(char *, int, char *, char *, int);
int	cfg_get_user_nopasswd(char *, int);
int	cfg_no_user_permitted(void);
char	*cfg_nodestring(int);
int	cfg_ppp_is_configured(char *, int);
int	cfg_read_config(char *);
int	cfg_user_exists(char *);
int	cfg_user_svc_default_is_permit(char *);

/* default_fn.c */
int	default_fn(struct authen_data *);
#ifdef MSCHAP
void	mschap_lmchallengeresponse(char *, char *, char *);
void	mschap_ntchallengeresponse(char *, char *, char *);
#endif
void	pw_bitshift(char *);
int	verify_host(char *, struct authen_data *, int, int);

/* enable.c */
int	verify(char *, char *, struct authen_data *, int);
int	verify_pwd(char *, char *, struct authen_data *, char *);

/* encrypt.c */
int	md5_xor(HDR *, u_char *, char *);

/* packet.c */
u_char	*get_authen_continue(void);
void	send_acct_reply(u_char, char *, char *);
void	send_authen_error(char *);
void	send_authen_reply(int, char *, u_short, char *, u_short, u_char);
void	send_author_reply(u_char, char *, char *, int, char **);
void	send_error_reply(int, char *);
u_char *read_packet(void);

/* parse.c */
char	*codestring(int);
int	keycode(char *);
void	parser_init(void);

/* programs.c */
int call_pre_process(char *, struct author_data *, char ***, int *, char *,
		     int);
int call_post_process(char *, struct author_data *, char ***, int *);

/* pw.c */
struct passwd *tac_passwd_lookup(char *, char *);

/* pwlib.c */
void	set_expiration_status(char *, struct authen_data *);
int	verify(char *, char *, struct authen_data *, int);
int	verify_pwd(char *, char *, struct authen_data *, char *);

int sendauth_fn(struct authen_data *data);
int sendpass_fn(struct authen_data *data);
int enable_fn(struct authen_data *data);
int default_v0_fn(struct authen_data *data);
int skey_fn(struct authen_data *data);

#ifdef MAXSESS
void loguser(struct acct_rec *);
void maxsess_loginit(void);
int maxsess_check_count(char *, struct author_data *);

extern char *wholog;
/*
 * This is state kept per user/session
 */
struct peruser {
    char username[64];		/* User name */
    char NAS_name[32];		/* NAS user logged into */
    char NAS_port[32];		/*  ...port on that NAS */
    char NAC_address[32];	/*  ...IP address of NAS */
};
#endif /* MAXSESS */

/* tac_plus.c */
void open_logfile(void);
