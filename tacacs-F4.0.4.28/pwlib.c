/*
 * $Id: pwlib.c,v 1.25 2009-03-17 18:40:20 heas Exp $
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
#include "expire.h"

#ifdef HAVE_CRYPT_H
# include <crypt.h>
#endif

#ifdef SHADOW_PASSWORDS
# include <shadow.h>
#endif

#if HAVE_PAM
# ifdef __APPLE__	/* MacOS X */
#  if __ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__ >= 1060
#   include <security/pam_appl.h>
#  else
#   include <pam/pam_appl.h>
#  endif
# else
#  include <security/pam_appl.h>
# endif
static int pam_tacacs(int, const struct pam_message **, struct pam_response **,
		      void *);
#endif

/*
 * Generic password verification routines for des, file, cleartext, and external passwords
 */
static int etc_passwd_file_verify(char *, char *, struct authen_data *);
static int des_verify(char *, char *);
#if HAVE_PAM
static int pam_verify(char *, char *, struct authen_data *data);
#endif
static int passwd_file_verify(char *, char *, struct authen_data *, char *);

static int external_verify_password(char *, char *, struct authen_data *, char *);

extern char *progname;

/* Adjust data->status depending on whether a user has expired or not */
void
set_expiration_status(char *exp_date, struct authen_data *data)
{
    int expired;

    /* if the status is anything except pass, there's no point proceeding */
    if (data->status != TAC_PLUS_AUTHEN_STATUS_PASS) {
	return;
    }

    /*
     * Check the expiration date, if any. If NULL, this check will return
     * PW_OK
     */
    expired = check_expiration(exp_date);

    switch (expired) {
    case PW_OK:
	if (debug & DEBUG_PASSWD_FLAG)
	    report(LOG_DEBUG, "Password has not expired %s",
		   exp_date ? exp_date : "<no expiry date set>");

	data->status = TAC_PLUS_AUTHEN_STATUS_PASS;
	break;

    case PW_EXPIRING:
	if (debug & DEBUG_PASSWD_FLAG)
	    report(LOG_DEBUG, "Password will expire soon %s",
		   exp_date ? exp_date : "<no expiry date set>");
	if (data->server_msg)
	    free(data->server_msg);
	data->server_msg = tac_strdup("Password will expire soon");
	data->status = TAC_PLUS_AUTHEN_STATUS_PASS;
	break;

    case PW_EXPIRED:
	if (debug & DEBUG_PASSWD_FLAG)
	    report(LOG_DEBUG, "Password has expired %s",
		   exp_date ? exp_date : "<no expiry date set>");
	if (data->server_msg)
	    free(data->server_msg);
	data->server_msg = tac_strdup("Password has expired");
	data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;
	break;

    default:
	report(LOG_ERR, "%s: Bogus return value %d from check_expiration",
	       session.peer, expired);
	data->status = TAC_PLUS_AUTHEN_STATUS_ERROR;
	break;
    }

    return;
}

/*
 * Verify that this user/password is valid.  Works only for cleartext, file,
 * PAM and des passwords.  Return 1 if password is valid.
 */
int
verify(char *name, char *passwd, struct authen_data *data, int recurse)
{
    char *exp_date;
    char *cfg_passwd;
    char *p;

    if (data->type == TAC_PLUS_AUTHEN_TYPE_PAP) {
	cfg_passwd = cfg_get_pap_secret(name, recurse);
    } else {
	cfg_passwd = cfg_get_login_secret(name, recurse);
    }

    /*
     * If there is no login or pap password for this user, see if there is
     * a global password that can be used.
     */
    if (cfg_passwd == NULL) {
	cfg_passwd = cfg_get_global_secret(name, recurse);
    }

    /*
     * If there is no login or pap password for this user, see if there is
     * a "default" user that can be used.
     */
    if ( !cfg_user_exists(name) )
    {
        /* If there is no global password for the user, try seeing if there is
          a password for the default userid */

        if ( !cfg_passwd) {
            cfg_passwd = cfg_get_login_secret(DEFAULT_USERNAME, recurse);
        }

        /* If there is no password for the default userid, try seeing if there
           is a global password for the default userid */

        if ( !cfg_passwd) {
            cfg_passwd = cfg_get_global_secret(DEFAULT_USERNAME, recurse);
        }
    }

    /*
     * If we still have no password for this user (or no user for that
     * matter) but the default authentication = file <file> statement
     * has been issued, attempt to use this password file
     */
    if (cfg_passwd == NULL) {
	char *file = cfg_get_authen_default();
	if (file) {
	    return(passwd_file_verify(name, passwd, data, file));
	}

	/* otherwise, we fail */
	data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;
	return(0);
    }

    /* We have a configured password. Deal with it depending on its type */
#if HAVE_PAM
    if (strcmp(cfg_passwd, "PAM") == 0) {
	/* try to verify the password via PAM */
	if (!pam_verify(name, passwd, data)) {
	    data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;
	    return(0);
	} else
	    data->status = TAC_PLUS_AUTHEN_STATUS_PASS;

	exp_date = cfg_get_expires(name, recurse);
	set_expiration_status(exp_date, data);
	return(data->status == TAC_PLUS_AUTHEN_STATUS_PASS);
    }
#endif

    p = tac_find_substring("cleartext ", cfg_passwd);
    if (p != NULL) {
	if (debug & DEBUG_PASSWD_FLAG)
	    report(LOG_DEBUG, "verify daemon %s == NAS %s", p, passwd);

	if (strcmp(passwd, p)) {
	    if (debug & DEBUG_PASSWD_FLAG)
		report(LOG_DEBUG, "Password is incorrect");
	    data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;
	    return(0);
	} else {
	    data->status = TAC_PLUS_AUTHEN_STATUS_PASS;

	    if (debug & DEBUG_PASSWD_FLAG)
		report(LOG_DEBUG, "Password is correct");
	}

	exp_date = cfg_get_expires(name, recurse);
	set_expiration_status(exp_date, data);
	return(data->status == TAC_PLUS_AUTHEN_STATUS_PASS);
    }

    p = tac_find_substring("des ", cfg_passwd);
    if (p) {
	/* try to verify this des password */
	if (!des_verify(passwd, p)) {
	    data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;
	    return(0);
	} else {
	    data->status = TAC_PLUS_AUTHEN_STATUS_PASS;
	}

	exp_date = cfg_get_expires(name, recurse);
	set_expiration_status(exp_date, data);
	return(data->status == TAC_PLUS_AUTHEN_STATUS_PASS);
    }

    p = tac_find_substring("external ", cfg_passwd);
    if (p) {
      /* try to verify this external password */
      if (!external_verify_password(name,passwd,data,p)) {
          data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;
          return (0);
      } else {
          data->status = TAC_PLUS_AUTHEN_STATUS_PASS;
      }

      exp_date = cfg_get_expires(name, recurse);
      set_expiration_status(exp_date, data);
      return (data->status == TAC_PLUS_AUTHEN_STATUS_PASS);
    }

    p = tac_find_substring("file ", cfg_passwd);
    if (p) {
	return(passwd_file_verify(name, passwd, data, p));
    }

    /*
     * Oops. No idea what kind of password this is. This should never
     * happen as the parser should never create such passwords.
     */
    report(LOG_ERR, "%s: Error cannot identify password type %s for %s",
	   session.peer,
	   cfg_passwd && cfg_passwd[0] ? cfg_passwd : "<NULL>",
	   name ? name : "<unknown>");

    data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;
    return(0);
}

/*
 * Verify that this user/password is valid for the matching password data,
 * such as "cleartext foopwd".  Works only for cleartext, des and file
 * passwords and is used only for or by enable().
 * Return 1 if password is valid.  The caller needs to check any expiration
 * dates itself.
 */
int
verify_pwd(char *username, char *passwd, struct authen_data *data,
	   char *cfg_passwd)
{
    char *p;

    /* Deal with the cfg_passwd depending on its type */
    p = tac_find_substring("cleartext ", cfg_passwd);
    if (p) {
	if (debug & DEBUG_PASSWD_FLAG)
	    report(LOG_DEBUG, "verify daemon %s == NAS %s", p, passwd);

	if (strcmp(passwd, p)) {
	    if (debug & DEBUG_PASSWD_FLAG)
		report(LOG_DEBUG, "Password is incorrect");
	    data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;
	    return(0);
	} else {
	    data->status = TAC_PLUS_AUTHEN_STATUS_PASS;

	    if (debug & DEBUG_PASSWD_FLAG)
		report(LOG_DEBUG, "Password is correct");
	}

	return(data->status == TAC_PLUS_AUTHEN_STATUS_PASS);
    }

    p = tac_find_substring("des ", cfg_passwd);
    if (p) {
	/* try to verify this des password */
	if (!des_verify(passwd, p)) {
	    data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;
	    return(0);
	} else {
	    data->status = TAC_PLUS_AUTHEN_STATUS_PASS;
	}

	return(data->status == TAC_PLUS_AUTHEN_STATUS_PASS);
    }

    p = tac_find_substring("file ", cfg_passwd);
    if (p) {
	if (!passwd_file_verify(username, passwd, data, p)) {
	    data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;
	    return(0);
	} else {
	    data->status = TAC_PLUS_AUTHEN_STATUS_PASS;
	}

	return(data->status == TAC_PLUS_AUTHEN_STATUS_PASS);
    }

    /* Oops. No idea what kind of password this is. This should never
     * happen as the parser should never create such passwords.
     */
    report(LOG_ERR, "%s: Error cannot identify password type %s for %s",
	   session.peer,
	   cfg_passwd && cfg_passwd[0] ? cfg_passwd : "<NULL>",
	   username ? username : "<unknown>");

    data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;
    return(0);
}

/* verify that this user/password is valid per /etc/passwd.  Return 0 if
 * invalid.
 */
static int
etc_passwd_file_verify(char *user, char *supplied_passwd,
		       struct authen_data *data)
{
    struct passwd *pw;
    char *exp_date;
    char *cfg_passwd;
#ifdef SHADOW_PASSWORDS
    char buf[12];
#endif /* SHADOW_PASSWORDS */

    data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;

    setpwent();
    pw = getpwnam(user);
    endpwent();

    if (pw == NULL) {
	/* no entry exists */
	return(0);
    }

    if (*pw->pw_passwd == '\0' ||
	supplied_passwd == NULL ||
	*supplied_passwd == '\0') {
	data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;
	return(0);
    }
    cfg_passwd = pw->pw_passwd;
    exp_date = pw->pw_shell;

#ifdef SHADOW_PASSWORDS
    if (STREQ(pw->pw_passwd, "x")) {
	struct spwd *spwd = getspnam(user);

	if (!spwd) {
	    if (debug & DEBUG_PASSWD_FLAG) {
		report(LOG_DEBUG, "No entry for %s in shadow file", user);
	    }
	    data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;
	    return(0);
	}
	if (debug & DEBUG_PASSWD_FLAG) {
	    report(LOG_DEBUG, "Found entry for %s in shadow file", user);
	}
	cfg_passwd = spwd->sp_pwdp;

	/*
	 * Sigh. The Solaris shadow password file contains its own
	 * expiry date as the number of days after the epoch
	 * (January 1, 1970) when the password expires.
	 * Convert this to ascii so that the traditional tacacs
	 * password expiration routines work correctly.
	 */
	if (spwd->sp_expire > 0) {
	    long secs = spwd->sp_expire * 24 * 60 * 60;
	    char *p = ctime(&secs);

	    memcpy(buf, p + 4, 7);
	    memcpy(buf + 7, p + 20, 4);
	    buf[11] = '\0';
	    exp_date = buf;
	}
    }
#endif /* SHADOW_PASSWORDS */

    /* try to verify the password */
    if (!des_verify(supplied_passwd, cfg_passwd)) {
	data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;
	return(0);
    } else {
	data->status = TAC_PLUS_AUTHEN_STATUS_PASS;
    }

    /* password ok. Check expiry field */
    set_expiration_status(exp_date, data);

    return(data->status == TAC_PLUS_AUTHEN_STATUS_PASS);
}

/*
 * verify that this user/password is valid per a passwd(5) style database.
 * Return 0 if invalid.
 */
static int
passwd_file_verify(char *user, char *supplied_passwd, struct authen_data *data,
		   char *filename)
{
    struct passwd *pw;
    char *exp_date;
    char *cfg_passwd;

    data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;

    if (filename && STREQ(filename, "/etc/passwd")) {
	return(etc_passwd_file_verify(user, supplied_passwd, data));
    }

    /* an alternate filename */
    if (!(access(filename, R_OK) == 0)) {
	report(LOG_ERR, "%s %s: Cannot access %s for user %s -- %s",
	       session.peer, session.port, filename, user, strerror(errno));
	return(0);
    }

    pw = tac_passwd_lookup(user, filename);

    if (pw == NULL)
	/* no entry exists */
	return(0);

    if (*pw->pw_passwd == '\0' ||
	supplied_passwd == NULL ||
	*supplied_passwd == '\0') {
	data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;
	return(0);
    }
    cfg_passwd = pw->pw_passwd;
    exp_date = pw->pw_shell;

    /* try to verify the password */
    if (!des_verify(supplied_passwd, cfg_passwd)) {
	data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;
	return(0);
    } else {
	data->status = TAC_PLUS_AUTHEN_STATUS_PASS;
    }

    /* password ok. Check expiry field */
    set_expiration_status(exp_date, data);
    return(data->status == TAC_PLUS_AUTHEN_STATUS_PASS);
}

/*
 * verify a provided password against a des encrypted one.  return 1 if
 * verified, 0 otherwise.
 */
static int
des_verify(char *users_passwd, char *encrypted_passwd)
{
    char *ep;

    if (debug & DEBUG_PASSWD_FLAG)
	report(LOG_DEBUG, "verify %s %s", users_passwd, encrypted_passwd);

    if (users_passwd == NULL ||
	*users_passwd == '\0' ||
	encrypted_passwd == NULL ||
	*encrypted_passwd == '\0') {
	if (debug & DEBUG_PASSWD_FLAG)
	    report(LOG_DEBUG, "verify returns 0");
	return(0);
    }

    ep = (char *)crypt(users_passwd, encrypted_passwd);

    if (debug & DEBUG_PASSWD_FLAG)
	report(LOG_DEBUG, "%s encrypts to %s", users_passwd, ep);

    if (strcmp(ep, encrypted_passwd) == 0) {
	if (debug & DEBUG_PASSWD_FLAG)
	    report(LOG_DEBUG, "Password is correct");
	return(1);
    }

    if (debug & DEBUG_PASSWD_FLAG)
	report(LOG_DEBUG, "Password is incorrect");

    return(0);
}

#if HAVE_PAM
/* pam_conv (PAM conversation) callback */
static int
pam_tacacs(int nmsg, const struct pam_message **pmpp, struct pam_response
	   **prpp, void *appdata_ptr)
{
    int i;
    struct authen_cont *acp;
    char *passwd = (char *)appdata_ptr;
    u_char *reply, *rp;

    if (debug & DEBUG_PASSWD_FLAG)
	report(LOG_DEBUG, "pam_tacacs received %d pam_messages", nmsg);

    if (nmsg <= 0 || nmsg > PAM_MAX_NUM_MSG)
	return(PAM_CONV_ERR);
    if ((*prpp = (struct pam_response *)
		 tac_malloc(nmsg * sizeof(struct pam_response))) == NULL)
	return(PAM_BUF_ERR);
    memset((struct pam_repsonse *)*prpp, 0,
	   nmsg * sizeof(struct pam_response));

    for (i = 0; i < nmsg; ++i) {
	switch (pmpp[i]->msg_style) {
	case PAM_PROMPT_ECHO_OFF:
	    if (debug & DEBUG_PASSWD_FLAG)
		report(LOG_DEBUG, "%s %s: PAM_PROMPT_ECHO_OFF", session.peer,
		       session.port);

	    /* pre-supplied password, such as service=PAP, or prompt for it */
	    if (passwd != NULL && strlen(passwd) > 0) {
		prpp[i]->resp = tac_strdup(passwd);
	    } else {
		send_authen_reply(TAC_PLUS_AUTHEN_STATUS_GETPASS,
				  (char *)pmpp[i]->msg,
				  pmpp[i]->msg ? strlen(pmpp[i]->msg) : 0,
				  NULL, 0, TAC_PLUS_AUTHEN_FLAG_NOECHO);
		reply = get_authen_continue();
		if (!reply) {
		    /* Typically due to a premature connection close */
		    report(LOG_ERR, "%s %s: Null reply packet, expecting "
			   "CONTINUE", session.peer, session.port);
 		    goto fail;
		}
		acp = (struct authen_cont *)(reply + TAC_PLUS_HDR_SIZE);

		rp = reply + TAC_PLUS_HDR_SIZE +
		     TAC_AUTHEN_CONT_FIXED_FIELDS_SIZE;
		/*
		 * A response to our GETDATA/GETPASS request. Create a
		 * null-terminated string for authen_data.
		 */
		prpp[i]->resp = (char *)tac_malloc(acp->user_msg_len + 1);
		memcpy(prpp[i]->resp, rp, acp->user_msg_len);
		prpp[i]->resp[acp->user_msg_len] = '\0';

		free(reply);
	    }
	    break;
	case PAM_PROMPT_ECHO_ON:
	    if (debug & DEBUG_PASSWD_FLAG)
		report(LOG_DEBUG, "%s %s: PAM_PROMPT_ECHO_ON", session.peer,
		       session.port);

	    send_authen_reply(TAC_PLUS_AUTHEN_STATUS_GETDATA,
			      (char *)pmpp[i]->msg,
			      pmpp[i]->msg ? strlen(pmpp[i]->msg) : 0,
			      NULL, 0, 0);
	    reply = get_authen_continue();
	    if (!reply) {
		/* Typically due to a premature connection close */
		report(LOG_ERR, "%s %s: Null reply packet, expecting CONTINUE",
		       session.peer, session.port);
 		goto fail;
	    }
	    acp = (struct authen_cont *)(reply + TAC_PLUS_HDR_SIZE);

	    rp = reply + TAC_PLUS_HDR_SIZE + TAC_AUTHEN_CONT_FIXED_FIELDS_SIZE;
	    /*
	     * A response to our GETDATA/GETPASS request. Create a
	     * null-terminated string for authen_data.
	     */
	    prpp[i]->resp = (char *)tac_malloc(acp->user_msg_len + 1);
	    memcpy(prpp[i]->resp, rp, acp->user_msg_len);
	    prpp[i]->resp[acp->user_msg_len] = '\0';

	    free(reply);
	    break;
	case PAM_ERROR_MSG:
	    send_authen_error((char *)pmpp[i]->msg);
	    break;
	case PAM_TEXT_INFO:
#ifdef PAM_MSG_NOCONF
	case PAM_MSG_NOCONF:
#endif
	    /* so we should not receive these with PAM_SILENT set */
	    break;
#ifdef PAM_CONV_INTERRUPT
	case PAM_CONV_INTERRUPT:
	    return(PAM_SUCCESS);
#endif
	default:
	    report(LOG_ERR, "%s %s: unknown pam_conv message type %d",
		   session.peer, session.port, pmpp[i]->msg_style);
	    goto fail;
	}
    }

    return(PAM_SUCCESS);
fail:
    for (i = 0; i < nmsg; ++i) {
	if ((*prpp)[i].resp != NULL) {
	    memset((*prpp)[i].resp, 0, strlen((*prpp)[i].resp));
	    free((*prpp)[i].resp);
	}
    }
    memset(*prpp, 0, nmsg * sizeof(struct pam_response));
    free(*prpp);
    *prpp = NULL;
    return(PAM_CONV_ERR);
}

/*
 * verify a provided user/password via PAM.
 * return 1 if verified, 0 otherwise.
 */
static int
pam_verify(char *user, char *passwd, struct authen_data *data)
{
    int			err;
    int     acct;
    int			pam_flag;
    struct pam_conv	conv = { pam_tacacs, passwd };
    pam_handle_t	*pamh = NULL;

    if (debug & DEBUG_PASSWD_FLAG)
	report(LOG_DEBUG, "pam_verify %s %s", user, passwd);

    if (user == NULL /* XXX || passwd == NULL || *passwd == '\0'*/) {
	if (debug & DEBUG_PASSWD_FLAG)
	    report(LOG_DEBUG, "pam_verify returns 0");
	return(0);
    }

    if ((err = pam_start(progname, user, &conv, &pamh)) != PAM_SUCCESS) {
	report(LOG_ERR, "pam_start failed: %s", pam_strerror(pamh, err));
	pam_end(pamh, err);
	if (debug & DEBUG_PASSWD_FLAG)
	    report(LOG_DEBUG, "pam_verify returns 0");
	return(0);
    }

    /* don't ignore PAM messages if password debugging is on */
    pam_flag = (debug & DEBUG_PASSWD_FLAG) ? 0 : PAM_SILENT;

    switch ((err = pam_authenticate(pamh, pam_flag))) {
    case PAM_SUCCESS:
      switch((acct = pam_acct_mgmt(pamh, pam_flag))) {
				case PAM_SUCCESS:
				  if (debug & DEBUG_PASSWD_FLAG)
					  report(LOG_DEBUG, "pam_acct_mgmt returns PAM_SUCCESS");
					pam_end(pamh, err);
					if (debug & DEBUG_PASSWD_FLAG)
						report (LOG_DEBUG, "pam_verify returns 1");
						return(1);
						break;
				case PAM_NEW_AUTHTOK_REQD:
					if (debug & DEBUG_PASSWD_FLAG)
						report(LOG_DEBUG, "pam_acct_mgmt returns PAM_NEW_AUTHTOK_REQD");
					if (data->server_msg)
					  free(data->server_msg);
					data->server_msg = tac_strdup("Password will expire soon, please change it immediately");
					break;
				case PAM_AUTHTOK_EXPIRED:
				  if (debug & DEBUG_PASSWD_FLAG)
					  report(LOG_DEBUG, "pam_acct_mgmt returns PAM_AUTHTOK_EXPIRED");
					if (data->server_msg)
					  free(data->server_msg);
					data->server_msg = tac_strdup("Password has expired");
					break;
				case PAM_ACCT_EXPIRED:
				  if (debug & DEBUG_PASSWD_FLAG)
					  report(LOG_DEBUG, "pam_acct_mgmt returns PAM_ACCT_EXPIRED");
					if (data->server_msg)
					  free(data->server_msg);
					data->server_msg = tac_strdup("Account has expired");
					break;
				default:
				  if (debug & DEBUG_PASSWD_FLAG)
					  report(LOG_DEBUG, "pam_account_mgmt returned unknown value %d",
						       acct);
						break;
			}
			break;
    case PAM_USER_UNKNOWN:
	    if (debug & DEBUG_PASSWD_FLAG)
	      report(LOG_DEBUG, "Unknown user");
	    break;
    case PAM_AUTH_ERR:
	if (debug & DEBUG_PASSWD_FLAG)
	    report(LOG_DEBUG, "Password is incorrect");
	break;
    default:
	if (debug & DEBUG_PASSWD_FLAG)
	    report(LOG_DEBUG, "pam_authenticate() returned unknown value %d",
		   err);
	break;
    }

    pam_end(pamh, err);
    return(0);
}
#endif

/*
 * verify a provided password using an external routine
 * external routine returns 0 if correct, 1 if incorrect
 *    routine interface similar to that of before/after authorization
 * subroutine returns 1 if verified, 0 otherwise.
 */

int
external_verify_password(char *user, char *passwd, struct authen_data *data, char *cmd)
{
    int status;
    char *value;
    char **out_args;
    char **in_args;
    int out_cnt, i, j;

    data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;

    if (debug & DEBUG_PASSWD_FLAG)
      report(LOG_DEBUG, "verify %s for %s using %s",
              passwd, user, cmd);

    if (passwd == NULL ||
      *passwd == '\0' ||
      user == NULL ||
      *user == '\0' ||
      cmd == NULL ||
      *cmd == '\0') {
      if (debug & DEBUG_PASSWD_FLAG)
          report(LOG_DEBUG, "verify returns 0 - something was NULL");
      return (0);
    }

    /* Allocate memory for 'user=USERID' and 'passwd=PASSWD' */
    in_args = (char **) malloc(2);
    in_args[0] = (char *) malloc( strlen(user)+strlen("user=")+1 );
    in_args[1] = (char *) malloc( strlen(passwd)+strlen("passwd=")+1 );
    sprintf(in_args[0], "user=%s", user);
    sprintf(in_args[1], "passwd=%s", passwd);

    status = call_external_auth_process(cmd, in_args, 2, &out_args, &out_cnt);

    free(in_args[0]);
    free(in_args[1]);

    /* throw away out_args, but keep message */
    for(i=0; i < out_cnt; i++) {
      value = tac_find_substring("msg=", out_args[i]);
      if ( value )
      {
          if ( data->server_msg ) { free(data->server_msg); }
          data->server_msg=tac_strdup(value);
      }
      free(out_args[i]);
    }
    free(out_args);

    switch (status) {
    default:
      if (debug & DEBUG_PASSWD_FLAG)
          report(LOG_DEBUG, "cmd %s returns %d (unrecognised value)",
                 cmd, status);
      return(0);

    case 0: /* Permit - Password Correct*/
      if (debug & DEBUG_PASSWD_FLAG)
          report(LOG_DEBUG, "cmd %s returns 0 (passwd correct)", cmd);
      data->status = TAC_PLUS_AUTHEN_STATUS_PASS;
      return(1);

    case 1: /* Deny - Password Incorrect*/
      if (debug & DEBUG_PASSWD_FLAG)
          report(LOG_DEBUG, "cmd %s returns 1 (passwd incorrect)", cmd);
      return(0);
    }

    return (0);
}

