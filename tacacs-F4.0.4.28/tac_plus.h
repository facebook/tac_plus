/*
 * $Id: tac_plus.h,v 1.55 2009/07/17 16:10:52 heas Exp $
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

#include "config.h"

/* use strerror() if we have one, else sys_errlist[errno] */
#ifndef HAVE_STRERROR
# define strerror(a)	sys_errlist[a]
#endif

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

#if HAVE_UTMP_H
# include <utmp.h>
#elif HAVE_UTMPX_H
# include <utmpx.h>
#endif

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

typedef struct tac_plus_pak_hdr HDR;

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

#define HASH_TAB_SIZE 65539        /* user and group hash table sizes */

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
typedef struct node {
    int type;     /* node type (arg, svc, proto) */
    void *next;   /* pointer to next node in chain */
    void *value;  /* node value */
    void *value1; /* node value */
    int dflt;     /* default value for node */
    int line;     /* line number declared on */
} NODE;

typedef union v {
    int intval;
    void *pval;
} VALUE;

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
void *hash_update_entry(void**, struct entry *);
void *hash_delete_entry(void**, char *);
void **hash_get_entries(void **);
void *hash_lookup(void **, char *);

/* client_count.c */
void client_count_init(void);
int get_client_count(char* client_ip);
int increment_client_count(char*);
int decrement_client_count(char*);
int decrement_client_count_for_proc(pid_t);
int increment_client_count_for_proc(pid_t, char *);
void remove_client_entry(char*);
void remove_proc_entry(char*);
void create_proc_client_map(pid_t, char*);
void delete_proc_client_map(pid_t);
void dump_client_tables();

struct client_st {
    char *name;     /* host name */
    void *hash;     /* hash table next pointer */
    int con_count;  /* count of connections from this peer */
};
typedef struct client_st CLIENT;

struct proc_st {
    char *name;     /* host name */
    void *hash;     /* hash table next pointer */
    char *client_ip; /* client ipv4 or ipv6 address */
};
typedef struct proc_st PROC_CLIENT;

/* config.c */
#ifdef ACLS
int	cfg_acl_check(char *, char *);
#endif
void	cfg_clean_config(void);
char	*cfg_get_arap_secret(char *, int);
char	*cfg_get_authen_default(void);
int     cfg_get_logauthor(void);
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
char	*cfg_nodestring(int);
int	cfg_ppp_is_configured(char *, int);
int	cfg_read_config(char *);
int	cfg_user_exists(char *);
int	cfg_user_svc_default_is_permit(char *);
int cfg_get_maxprocs(void);
int cfg_get_maxprocsperclt(void);

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
int call_external_auth_process(char *, char **, int, char ***, int *);

/* pw.c */
struct passwd *tac_passwd_lookup(char *, char *);

/* pwlib.c */
void	set_expiration_status(char *, struct authen_data *);
int	verify(char *, char *, struct authen_data *, int);
int	verify_pwd(char *, char *, struct authen_data *, char *);

int aceclnt_fn(struct authen_data *data);
int default_v0_fn(struct authen_data *data);
int enable_fn(struct authen_data *data);
int sendauth_fn(struct authen_data *data);
int sendpass_fn(struct authen_data *data);
int skey_fn(struct authen_data *data);

/* tac_plus.c */
void open_logfile(void);

int maxsess_check_count(char *, struct author_data *);
