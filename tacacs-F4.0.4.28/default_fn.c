/*
 * $Id: default_fn.c,v 1.14 2009-03-17 18:38:12 heas Exp $
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
#include "md5.h"

#ifdef MSCHAP
# include "md4.h"
# include "mschap.h"
#endif

#if ARAP_DES || MSCHAP_DES
# include "fdes.h"
#endif

/* internal state variables */
#define STATE_AUTHEN_START   0	/* no requests issued */
#define STATE_AUTHEN_GETUSER 1	/* username has been requested */
#define STATE_AUTHEN_GETPASS 2	/* password has been requested */

struct private_data {
    char password[MAX_PASSWD_LEN + 1];
    int state;
};

static void arap_verify(struct authen_data *);
static void chap_verify(struct authen_data *);
#ifdef MSCHAP
static void mschap_challengeresponse(char *, char *, char *);
static void mschap_desencrypt(char *, unsigned char *, unsigned char *);
static void mschap_deshash(char *, char *);
static void mschap_lmpasswordhash(char *, char *);
static void mschap_ntpasswordhash(char *, char *);
static void mschap_verify(struct authen_data *);
static int mschap_unicode_len(char *);
#endif /* MSCHAP */
static void pap_verify(struct authen_data *);
static void tac_login(struct authen_data *, struct private_data *);

/*
 * Default tacacs login authentication function. Wants a username
 * and a password, and tries to verify them.
 *
 * Choose_authen will ensure that we already have a username before this
 * gets called.
 *
 * We will query for a password and keep it in the method_data.
 *
 * Any strings returned via pointers in authen_data must come from the
 * heap. They will get freed by the caller.
 *
 * Return 0 if data->status is valid, otherwise 1
 */
int
default_fn(struct authen_data *data)
{
    struct private_data *p;
    char *name = data->NAS_id->username;
    char *clientip = ((data->NAS_id->NAC_address) && data->NAS_id->NAC_address[0]) ?
      data->NAS_id->NAC_address : "unknown";

    p = (struct private_data *) data->method_data;

    /* An abort has been received. Clean up and return */
    if (data->flags & TAC_PLUS_CONTINUE_FLAG_ABORT) {
	if (data->method_data)
	    free(data->method_data);
	data->method_data = NULL;
	return(1);
    }
    /* Initialise method_data if first time through */
    if (!p) {
	p = (struct private_data *) tac_malloc(sizeof(struct private_data));
	memset(p, 0, sizeof(struct private_data));
	data->method_data = p;
	p->state = STATE_AUTHEN_START;
    }
    if (STREQ(name, DEFAULT_USERNAME)) {
	/* Never authenticate this user. It's for authorization only */
	data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;
	if (debug) {
	    report(LOG_DEBUG,
		   "authentication query for '%s' port %s from %s rejected",
		   (name != NULL && name[0] != '\0') ? name : "unknown",
		   session.port, session.peer);
	}
	return(0);
    }
    if (data->action != TAC_PLUS_AUTHEN_LOGIN) {
	data->status = TAC_PLUS_AUTHEN_STATUS_ERROR;
    } else {
	switch (data->type) {
	case TAC_PLUS_AUTHEN_TYPE_CHAP:
	    /* set status inside chap_verify */
	    chap_verify(data);

	    if (debug) {
		report(LOG_DEBUG,
		       "chap-login query for '%s' port %s from %s %s",
		       (name != NULL && name[0] != '\0') ? name : "unknown",
		       session.port, session.peer,
		       (data->status == TAC_PLUS_AUTHEN_STATUS_PASS) ?
		       "accepted" : "rejected");
	    }
	    break;

#ifdef MSCHAP
	case TAC_PLUS_AUTHEN_TYPE_MSCHAP:
	    /* set status inside mschap_verify */
	    mschap_verify(data);

	    if (debug) {
		report(LOG_DEBUG,
		       "mschap-login query for '%s' port %s from %s %s",
		       (name != NULL && name[0] != '\0') ? name : "unknown",
		       session.port, session.peer,
		       (data->status == TAC_PLUS_AUTHEN_STATUS_PASS) ?
		       "accepted" : "rejected");
	    }
	    break;
#endif /* MSCHAP */

	case TAC_PLUS_AUTHEN_TYPE_ARAP:
	    /* set status inside arap_verify */
	    arap_verify(data);

	    if (debug) {
		report(LOG_DEBUG, "arap query for '%s' port %s from %s %s",
		       (name != NULL && name[0] != '\0') ? name : "unknown",
		       session.port, session.peer,
		       (data->status == TAC_PLUS_AUTHEN_STATUS_PASS) ?
		       "accepted" : "rejected");
	    }
	    break;

	case TAC_PLUS_AUTHEN_TYPE_PAP:
	    pap_verify(data);

	    if (debug) {
		report(LOG_DEBUG, "pap-login query for '%s' port %s from %s %s",
		       (name != NULL && name[0] != '\0') ? name : "unknown",
		       session.port,
		       session.peer,
		       (data->status == TAC_PLUS_AUTHEN_STATUS_PASS) ?
		       "accepted" : "rejected");
	    }
	    break;

	case TAC_PLUS_AUTHEN_TYPE_ASCII:
	    tac_login(data, p);
	    switch (data->status) {
	    case TAC_PLUS_AUTHEN_STATUS_GETPASS:
	    case TAC_PLUS_AUTHEN_STATUS_GETUSER:
	    case TAC_PLUS_AUTHEN_STATUS_GETDATA:
		/* Authentication still in progress. More data required */
		return(0);

	    default:
		/* Authentication finished */
		if (debug)
		    report(LOG_DEBUG, "login query for '%s' port %s from %s %s",
			   (name != NULL && name[0] != '\0') ? name : "unknown",
			   session.port,
			   session.peer,
			   (data->status == TAC_PLUS_AUTHEN_STATUS_PASS) ?
			   "accepted" : "rejected");
	    }
	    break;

	default:
	    data->status = TAC_PLUS_AUTHEN_STATUS_ERROR;
	    break;
	}
    }

    if (data->method_data)
	free(data->method_data);
    data->method_data = NULL;

    switch (data->status) {
    case TAC_PLUS_AUTHEN_STATUS_ERROR:
	    return(0);
    case TAC_PLUS_AUTHEN_STATUS_FAIL:
	    if (session.peer)
	      report(LOG_NOTICE, "login failure: user=%s device=%s ip=%s port=%s client=%s",
		     name == NULL ? "unknown" : name,
		     session.peer, session.peerip, session.port, clientip);
	    else
	      report(LOG_NOTICE, "login failure: user=%s device=%s port=%s",
		     name == NULL ? "unknown" : name,
		     session.peerip, session.port);
      return(0);
    case TAC_PLUS_AUTHEN_STATUS_PASS:
      if (session.peer)
        report(LOG_NOTICE, "login success: user=%s device=%s ip=%s port=%s client=%s",
         name == NULL ? "unknown" : name,
         session.peer, session.peerip, session.port, clientip);
      else
        report(LOG_NOTICE, "login failure: user=%s device=%s port=%s",
         name == NULL ? "unknown" : name,
         session.peerip, session.port);
	    return(0);

    default:
	    report(LOG_ERR, "%s %s: default_fn set bogus status value %d",
	     session.peer, session.port, data->status);
	     data->status = TAC_PLUS_AUTHEN_STATUS_ERROR;
	return(0);
    }
}

/*
 * Do a login requiring a username & password. We already know the
 * username. We may return GETPASS to get a password if we need it.
 * The password will be stored in the private data
 */
static void
tac_login(struct authen_data *data, struct private_data *p)
{
#if HAVE_PAM
    char	*cfg_passwd;
#endif
    char	*name, *passwd;
    int		pwlen;

    name = data->NAS_id->username;

    if (!name[0]) {
	/* something awful has happened. Give up and die */
	report(LOG_ERR, "%s %s: no username for login",
	       session.peer, session.port);
	data->status = TAC_PLUS_AUTHEN_STATUS_ERROR;
	return;
    }
    /* Do we have a password? */
    passwd = p->password;

    if (!passwd[0]) {
	/*
	 * no password yet. Either we need to ask for one and expect to get
	 * called again when it's supplied, or we already asked for one and
	 * we should have a reply.
	 */
	switch (p->state) {
	case STATE_AUTHEN_GETPASS:
	    /* We already asked for a password. This should be the reply */
	    if (data->client_msg) {
		pwlen = MIN((int) strlen(data->client_msg), MAX_PASSWD_LEN);
	    } else {
		pwlen = 0;
	    }
	    strncpy(passwd, data->client_msg, pwlen);
	    passwd[pwlen] = '\0';
	    break;

	case STATE_AUTHEN_START:
	    /*
	     * if we're at the username stage, and the user has nopasswd
	     * defined, then return a PASS.
	     */
	    if (cfg_get_user_nopasswd(name, TAC_PLUS_RECURSE)) {
		data->status = TAC_PLUS_AUTHEN_STATUS_PASS;
		return;
	    }
#if HAVE_PAM
	    /* if the authen method is PAM, let PAM prompt for the password */
	    if ((cfg_passwd = cfg_get_login_secret(name, TAC_PLUS_RECURSE))
		!= NULL) {
		if (strcmp(cfg_passwd, "PAM") == 0)
		    break;
	    }
#endif
	    /* FALL-THRU */
	default:
	    data->flags = TAC_PLUS_AUTHEN_FLAG_NOECHO;
	    data->server_msg = tac_strdup("Password: ");
	    data->status = TAC_PLUS_AUTHEN_STATUS_GETPASS;
	    p->state = STATE_AUTHEN_GETPASS;
	    return;
	}
    }
    /* Now we have a username and password. Try validating */

    /* Assume the worst */
    data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;
    verify(name, passwd, data, TAC_PLUS_RECURSE);
#ifdef ACLS
    if (verify_host(name, data, S_acl, TAC_PLUS_RECURSE) != S_permit)
	data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;
#endif
    return;
}

/*
 * Process an inbound PAP login. The username & password should be in
 * the START packet.
 */
static void
pap_verify(struct authen_data *data)
{
    char *name, *passwd;

    name = data->NAS_id->username;

    if (name[0] == '\0') {
	/* something awful has happened. Give up and die */
	report(LOG_ERR, "%s %s: no username for inbound PAP login",
	       session.peer, session.port);
	data->status = TAC_PLUS_AUTHEN_STATUS_ERROR;
	return;
    }
    /* get the password */
    passwd = tac_malloc(data->client_dlen + 1);
    memcpy(passwd, data->client_data, data->client_dlen);
    passwd[data->client_dlen] = '\0';

    /* Assume the worst */
    data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;
    verify(name, passwd, data, TAC_PLUS_RECURSE);
#ifdef ACLS
    if (verify_host(name, data, S_acl, TAC_PLUS_RECURSE) != S_permit)
	data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;
#endif
    free(passwd);
    return;
}

/* Verify the challenge and id against the response by looking up the
 * chap secret in the config file. Set data->status appropriately.
 */
static void
chap_verify(struct authen_data *data)
{
    char *name, *secret, *chal, digest[TAC_MD5_DIGEST_LEN];
    char *exp_date, *p;
    u_char *mdp;
    char id;
    int chal_len, inlen;
    MD5_CTX mdcontext;

    if (!(char) data->NAS_id->username[0]) {
	report(LOG_ERR, "%s %s: no username for chap_verify",
	       session.peer, session.port);
	data->status = TAC_PLUS_AUTHEN_STATUS_ERROR;
	return;
    }
    name = data->NAS_id->username;

    id = data->client_data[0];

    chal_len = data->client_dlen - 1 - TAC_MD5_DIGEST_LEN;
    if (chal_len < 0) {
	data->status = TAC_PLUS_AUTHEN_STATUS_ERROR;
	return;
    }
    if (debug & DEBUG_AUTHEN_FLAG) {
	report(LOG_DEBUG, "%s %s: chap user=%s, id=%d chal_len=%d",
	       session.peer, session.port, name, (int) id, chal_len);

	/* report_hex(LOG_DEBUG, (u_char *)data->client_data + 1, chal_len); */
    }
    /* Assume failure */
    data->status = TAC_PLUS_AUTHEN_STATUS_ERROR;

    /* Get the secret */
    secret = cfg_get_chap_secret(name, TAC_PLUS_RECURSE);

    /*
     * If there is no chap password for this user, see if there is a global
     * password for her that we can use
     */
    if (!secret) {
	secret = cfg_get_global_secret(name, TAC_PLUS_RECURSE);
    }
    if (!secret) {
	/* No secret. Fail */
	if (debug & DEBUG_AUTHEN_FLAG) {
	    report(LOG_DEBUG, "%s %s: No chap or global secret for %s",
		   session.peer, session.port, name);
	}
	data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;
	return;
    }
    p = tac_find_substring("cleartext ", secret);
    if (!p) {
	report(LOG_ERR, "%s %s: %s chap secret %s is not cleartext",
	       session.peer, session.port, name, secret);
	data->status = TAC_PLUS_AUTHEN_STATUS_ERROR;
	return;
    }
    secret = p;

    /*
     * We now have the secret, the id, and the challenge value. Put them all
     * together, and run them through the MD5 digest algorithm.
     */
    inlen = sizeof(u_char) + strlen(secret) + chal_len;
    mdp = (u_char *) tac_malloc(inlen);
    mdp[0] = id;
    memcpy(&mdp[1], secret, strlen(secret));
    chal = data->client_data + 1;
    memcpy(mdp + strlen(secret) + 1, chal, chal_len);
    MD5Init(&mdcontext);
    MD5Update(&mdcontext, mdp, inlen);
    MD5Final((u_char *) digest, &mdcontext);
    free(mdp);

    /*
     * Now compare the received response value with the just calculated
     * digest value.  If they are equal, it's a pass, otherwise it's a
     * failure
     */
    if (memcmp(digest, data->client_data + 1 + chal_len, TAC_MD5_DIGEST_LEN)) {
	data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;
    } else {
	data->status = TAC_PLUS_AUTHEN_STATUS_PASS;
    }

#ifdef ACLS
    if (verify_host(name, data, S_acl, TAC_PLUS_RECURSE) != S_permit)
	data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;
#endif

    exp_date = cfg_get_expires(name, TAC_PLUS_RECURSE);
    set_expiration_status(exp_date, data);
    return;
}

/*
 * Force the "parity" bit to zero on a password before passing it to
 * des. This is not documented anywhere. (I believe forcing the parity
 * to zero reduces the integrity of the encrypted keys but this is
 * what Apple chose to do).
 */
void
pw_bitshift(char *pw)
{
    int i;
    unsigned char pws[8];

    /* key is 0 padded */
    for (i = 0; i < 8; i++)
	pws[i] = 0;

    /* parity bit is always zero (this seem bogus) */
    for (i = 0; i < 8 && pw[i]; i++)
	pws[i] = pw[i] << 1;

    memcpy(pw, pws, 8);
    return;
}

static void
arap_verify(struct authen_data *data)
{
    char nas_chal[8], r_chal[8], r_resp[8], secret[8];
    char *name, *cfg_secret, *exp_date, *p;
#ifdef ARAP_DES
    union LR_block desblk;
#endif

    if (!(char) data->NAS_id->username[0]) {
	report(LOG_ERR, "%s %s: no username for arap_verify",
	       session.peer, session.port);
	data->status = TAC_PLUS_AUTHEN_STATUS_ERROR;
	return;
    }
    name = data->NAS_id->username;

    memcpy(nas_chal, data->client_data, 8);
    memcpy(r_chal, data->client_data + 8, 8);
    memcpy(r_resp, data->client_data + 8 + 8, 8);

    /* Assume failure */
    data->status = TAC_PLUS_AUTHEN_STATUS_ERROR;

    /* Get the secret */
    cfg_secret = cfg_get_arap_secret(name, TAC_PLUS_RECURSE);

    /*
     * If there is no arap password for this user, see if there is a global
     * password for her that we can use.
     */
    if (!cfg_secret) {
	cfg_secret = cfg_get_global_secret(name, TAC_PLUS_RECURSE);
    }
    if (!cfg_secret) {
	/* No secret. Fail */
	if (debug & DEBUG_AUTHEN_FLAG) {
	    report(LOG_DEBUG, "%s %s: No arap or global secret for %s",
		   session.peer, session.port, name);
	}
	data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;
	return;
    }
    p = tac_find_substring("cleartext ", cfg_secret);
    if (!p) {
	report(LOG_ERR, "%s %s: %s arap secret %s is not cleartext",
	       session.peer, session.port, name, cfg_secret);
	data->status = TAC_PLUS_AUTHEN_STATUS_ERROR;
	return;
    }
    /* need to allocate 8 bytes for secret, even if it's actually shorter */
    memset(secret, 0, sizeof(secret));
    memcpy(secret, p, strlen(p) <= 8 ? strlen(p) : 8);

    pw_bitshift(secret);

#ifdef ARAP_DES
    tac_set_des_mode(DES_MODE_ENCRYPT);
    tac_des_loadkey(secret, DES_KEY_SHIFT);
    memcpy(desblk.string, nas_chal, 8);
    tac_des(&desblk);
    memcpy(nas_chal, desblk.string, 8);
#endif

    /*
     * Now compare the remote's response value with the one just calculated.
     * If they are equal, it's a pass, otherwise it's a failure.
     */
    if (memcmp(nas_chal, r_resp, 8)) {
	data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;
    } else {
	data->status = TAC_PLUS_AUTHEN_STATUS_PASS;
    }

#ifdef ARAP_DES
    /* Now calculate the response to the remote's challenge */
    tac_set_des_mode(DES_MODE_ENCRYPT);
    tac_des_loadkey(secret, DES_KEY_SHIFT);
    memcpy(desblk.string, r_chal, 8);
    tac_des(&desblk);
    memcpy(r_chal, desblk.string, 8);
#endif

    data->server_data = tac_malloc(8);
    data->server_dlen = 8;
    memcpy(data->server_data, r_chal, 8);

#ifdef ACLS
    if (verify_host(name, data, S_acl, TAC_PLUS_RECURSE) != S_permit)
	data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;
#endif

    exp_date = cfg_get_expires(name, TAC_PLUS_RECURSE);
    set_expiration_status(exp_date, data);
    return;
}

#ifdef MSCHAP
/* Following code is added for ms-chap */
static void
mschap_desencrypt(char *clear, unsigned char *str, unsigned char *cypher)
{
    unsigned char key[8];
#ifdef MSCHAP_DES
    union LR_block desblk;
#endif

    /* XXX des_state_type *des_state = NULL; */

    memset(key, 0, 8);

    /* Copy the key inserting parity bits */

#ifdef old
    /* This method makes it obvious what we are doing */
#define getbit(bit,array) ((array[bit/8] & (1 <<  (7-(bit%8)))) !=0)
#define setbit(bit,array) (array[bit/8] |= (1 <<  (7-(bit%8))))
    {
	int i, j;

	j = 0;
	for (i = 0; i < 56; i++) {
	    if (i && (i % 7 == 0)) {
		j++;
	    }
	    if (getbit(i, str))
		setbit(j, key);
	    j++;
	}
    }
#else
    /*
     * this is a little more cryptic, but faster basicly we are inserting a
     * bit into the stream after every 7 bits.
     */
    key[0] = ((str[0] & 0xfe));
    key[1] = ((str[0] & 0x01) << 7) | ((str[1] & 0x0fc) >> 1);
    key[2] = ((str[1] & 0x03) << 6) | ((str[2] & 0x0f8) >> 2);
    key[3] = ((str[2] & 0x07) << 5) | ((str[3] & 0x0f0) >> 3);
    key[4] = ((str[3] & 0x0f) << 4) | ((str[4] & 0x0e0) >> 4);
    key[5] = ((str[4] & 0x1f) << 3) | ((str[5] & 0x0c0) >> 5);
    key[6] = ((str[5] & 0x3f) << 2) | ((str[6] & 0x080) >> 6);
    key[7] = ((str[6] & 0x7f) << 1);
#endif

    /* copy clear to cypher, cause our des encrypts in place */
    memcpy(cypher, clear, 8);
/*
XXX
    des_init(0,&des_state);
    des_setkey(des_state,key);
    des_endes(des_state,cypher);
    des_done(des_state);
*/
#ifdef MSCHAP_DES
    tac_set_des_mode(DES_MODE_ENCRYPT);
    tac_des_loadkey(key, DES_KEY_SHIFT);
    memcpy(desblk.string, cypher, 8);
    tac_des(&desblk);
    memcpy(cypher, desblk.string, 8);
#endif
    return;
}

static void
mschap_deshash(char *clear, char *cypher)
{
    mschap_desencrypt(MSCHAP_KEY, clear, cypher);
    return;
}

static void
mschap_lmpasswordhash(char *password, char *passwordhash)
{
    unsigned char upassword[15];
    int i = 0;

    memset(upassword, 0, 15);
    while (password[i]) {
	upassword[i] = toupper(password[i]);
	i++;
    };

    mschap_deshash(&upassword[0], &passwordhash[0]);
    mschap_deshash(&upassword[7], &passwordhash[8]);
    return;
}

static void
mschap_challengeresponse(char *challenge, char *passwordhash, char *response)
{
    char zpasswordhash[21];

    memset(zpasswordhash, 0, 21);
    memcpy(zpasswordhash, passwordhash, 16);

    mschap_desencrypt(challenge, &zpasswordhash[0], &response[0]);
    mschap_desencrypt(challenge, &zpasswordhash[7], &response[8]);
    mschap_desencrypt(challenge, &zpasswordhash[14], &response[16]);
    return;
}

void
mschap_lmchallengeresponse(char *challenge, char *password, char *response)
{
    char passwordhash[16];

    mschap_lmpasswordhash(password, passwordhash);
    mschap_challengeresponse(challenge, passwordhash, response);
    return;
}

static int
mschap_unicode_len(char *password)
{
    int i;

    i = 0;
    while ((password[i] || password[i + 1]) && (i < 512)) {
	i += 2;
    }

    return i;
}

static void
mschap_ntpasswordhash(char *password, char *passwordhash)
{
    MD4_CTX context;
    int i;
    char *cp;
    unsigned char unicode_password[512];

    memset(unicode_password, 0, 512);

    i = 0;
    memset(unicode_password, 0, 512);
    cp = password;
    while (*cp) {
	unicode_password[i++] = *cp++;
	unicode_password[i++] = '\0';
    }

    MD4Init(&context);
    MD4Update(&context, unicode_password,
	      mschap_unicode_len(unicode_password));
    MD4Final(passwordhash, &context);
    return;
}

void
mschap_ntchallengeresponse(char *challenge, char *password, char *response)
{
    char passwordhash[16];

    mschap_ntpasswordhash(password, passwordhash);
    mschap_challengeresponse(challenge, passwordhash, response);
    return;
}

/*
 * Verify the challenge and id against the response by looking up the
 * ms-chap secret in the config file. Set data->status appropriately.
 */
static void
mschap_verify(struct authen_data *data)
{
    char *name, *secret, *chal, *resp;
    char *exp_date, *p;
    char id;
    int chal_len;
    char lmresponse[24];
    char ntresponse[24];
    int memcmp_status;

    if (!(char) data->NAS_id->username[0]) {
	report(LOG_ERR, "%s %s: no username for mschap_verify",
	       session.peer, session.port);
	data->status = TAC_PLUS_AUTHEN_STATUS_ERROR;
	return;
    }
    name = data->NAS_id->username;

    id = data->client_data[0];

    chal_len = data->client_dlen - 1 - MSCHAP_DIGEST_LEN;
    if (data->client_dlen <= (MSCHAP_DIGEST_LEN + 2)) {
	/* Invalid packet or NULL challenge */
	data->status = TAC_PLUS_AUTHEN_STATUS_ERROR;
	return;
    }
    if (debug & DEBUG_AUTHEN_FLAG) {
	report(LOG_DEBUG, "%s %s: ms-chap user=%s, id=%d chal_len=%d",
	       session.peer, session.port, name, (int) id, chal_len);

	/* XXX report_hex(LOG_DEBUG, (u_char *)data->client_data + 1, chal_len); */
    }
    /* Assume failure */
    data->status = TAC_PLUS_AUTHEN_STATUS_ERROR;

    /* Get the secret */
    secret = cfg_get_mschap_secret(name, TAC_PLUS_RECURSE);

    /*
     * If there is no ms-chap password for this user, see if there is a
     * global password for her that we can use
     */
    if (!secret) {
	secret = cfg_get_global_secret(name, TAC_PLUS_RECURSE);
    }
    if (!secret) {
	/* No secret. Fail */
	if (debug & DEBUG_AUTHEN_FLAG) {
	    report(LOG_DEBUG, "%s %s: No ms-chap or global secret for %s",
		   session.peer, session.port, name);
	}
	data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;
	return;
    }
    p = tac_find_substring("cleartext ", secret);
    if (!p) {
	report(LOG_ERR, "%s %s: %s ms-chap secret %s is not cleartext",
	       session.peer, session.port, name, secret);
	data->status = TAC_PLUS_AUTHEN_STATUS_ERROR;
	return;
    }
    secret = p;

    /*
     * We now have the secret, the id, and the challenge value. Put them all
     * together, and run them through the MD4 digest algorithm.
     */
    chal = data->client_data + 1;
    resp = data->client_data + 1 + chal_len;

    mschap_lmchallengeresponse(chal, secret, lmresponse);
    mschap_ntchallengeresponse(chal, secret, ntresponse);

    /*
     * Now compare the received response value with the just calculated
     * digest value.  If they are equal, it's a pass, otherwise it's a
     * failure.
     */
    if (resp[48])
	memcmp_status = memcmp(ntresponse, &resp[24], 24);
    else
	memcmp_status = memcmp(lmresponse, &resp[0], 24);

    if (memcmp_status) {
	data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;
    } else {
	data->status = TAC_PLUS_AUTHEN_STATUS_PASS;
    }

#ifdef ACLS
    if (verify_host(name, data, S_acl, TAC_PLUS_RECURSE) != S_permit)
	data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;
#endif

    exp_date = cfg_get_expires(name, TAC_PLUS_RECURSE);
    set_expiration_status(exp_date, data);
    return;
}
#endif /* MSCHAP */

#ifdef ACLS
/*
 * Verify that the NAS's peerip matches the host acl filter.
 * Return S_deny if session.peerip is invalid, else S_permit
 */
int
verify_host(char *name, struct authen_data *data, int type, int recurse)
{
    char *realname, *val;
    int status;

    /* lookup host acl for user */
    if (!cfg_user_exists(name) && cfg_user_exists(DEFAULT_USERNAME)) {
	if (debug & DEBUG_AUTHEN_FLAG) {
	    report(LOG_DEBUG, "Authenticating ACLs for user '%s' instead of "
		   "'%s'", DEFAULT_USERNAME, name);
	}
	realname = DEFAULT_USERNAME;
    } else
	realname = name;
    val = cfg_get_pvalue(realname, 1, type, recurse);

    /* no host acl for user */
    if (val == NULL)
	return(S_permit);

    if ((status = cfg_acl_check(val, data->NAS_id->NAS_ip)) != S_permit) {
	if (debug & DEBUG_AUTHEN_FLAG)
	    report(LOG_DEBUG, "host ACLs for user '%s' deny", realname);
    } else
	if (debug & DEBUG_AUTHEN_FLAG)
	    report(LOG_DEBUG, "host ACLs for user '%s' permit", realname);

    return(status);
}
#endif
