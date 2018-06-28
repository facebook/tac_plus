/*
 * $Id: encrypt.c,v 1.8 2009-03-17 18:38:12 heas Exp $
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
#include "md5.h"

/*
 * create_md5_hash(): create an md5 hash of the "session_id", "the user's
 * key", "the version number", the "sequence number", and an optional
 * 16 bytes of data (a previously calculated hash). If not present, this
 * should be NULL pointer.
 *
 * Write resulting hash into the array pointed to by "hash".
 *
 * The caller must allocate sufficient space for the resulting hash
 * (which is 16 bytes long). The resulting hash can safely be used as
 * input to another call to create_md5_hash, as its contents are copied
 * before the new hash is generated.
 */
void
create_md5_hash(int session_id, char *key, u_char version, u_char seq_no,
		u_char *prev_hash, u_char *hash)
{
    u_char *md_stream, *mdp;
    int md_len;
    MD5_CTX mdcontext;

    md_len = sizeof(session_id) + strlen(key) + sizeof(version) +
	sizeof(seq_no);

    if (prev_hash) {
	md_len += TAC_MD5_DIGEST_LEN;
    }
    mdp = md_stream = (u_char *) tac_malloc(md_len);
    memcpy(mdp, &session_id, sizeof(session_id));
    mdp += sizeof(session_id);

    memcpy(mdp, key, strlen(key));
    mdp += strlen(key);

    memcpy(mdp, &version, sizeof(version));
    mdp += sizeof(version);

    memcpy(mdp, &seq_no, sizeof(seq_no));
    mdp += sizeof(seq_no);

    if (prev_hash) {
	memcpy(mdp, prev_hash, TAC_MD5_DIGEST_LEN);
	mdp += TAC_MD5_DIGEST_LEN;
    }
    MD5Init(&mdcontext);
    MD5Update(&mdcontext, md_stream, md_len);
    MD5Final(hash, &mdcontext);
    free(md_stream);
    return;
}

/*
 * Overwrite input data with en/decrypted version by generating an MD5 hash and
 * xor'ing data with it.
 *
 * When more than 16 bytes of hash is needed, the MD5 hash is performed
 * again with the same values as before, but with the previous hash value
 * appended to the MD5 input stream.
 *
 * Return 0 on success, -1 on failure.
 */
int
md5_xor(HDR *hdr, u_char *data, char *key)
{
    int i, j;
    u_char hash[TAC_MD5_DIGEST_LEN];	/* the md5 hash */
    u_char last_hash[TAC_MD5_DIGEST_LEN];	/* the last hash we generated */
    u_char *prev_hashp = (u_char *) NULL;	/* pointer to last created
						 * hash */
    int data_len;
    int session_id;
    u_char version;
    u_char seq_no;

    data_len = ntohl(hdr->datalength);
    session_id = hdr->session_id; /* always in network order for hashing */
    version = hdr->version;
    seq_no = hdr->seq_no;

    if (!key)
	return(0);

    for (i = 0; i < data_len; i += 16) {
	create_md5_hash(session_id, key, version, seq_no, prev_hashp, hash);

	if (debug & DEBUG_MD5_HASH_FLAG) {
	    int k;

	    report(LOG_DEBUG,
		   "hash: session_id=%u, key=%s, version=%d, seq_no=%d",
		   session_id, key, version, seq_no);
	    if (prev_hashp) {
		report(LOG_DEBUG, "prev_hash:");
		for (k = 0; k < TAC_MD5_DIGEST_LEN; k++)
		    report(LOG_DEBUG, "0x%x", prev_hashp[k]);
	    } else {
		report(LOG_DEBUG, "no prev. hash");
	    }

	    report(LOG_DEBUG, "hash: ");
	    for (k = 0; k < TAC_MD5_DIGEST_LEN; k++)
		report(LOG_DEBUG, "0x%x", hash[k]);
	}
	memcpy(last_hash, hash, TAC_MD5_DIGEST_LEN);
	prev_hashp = last_hash;

	for (j = 0; j < 16; j++) {
	    if ((i + j) >= data_len) {
		if (hdr->flags & TAC_PLUS_UNENCRYPTED)
		    hdr->flags &= ~TAC_PLUS_UNENCRYPTED;
		else
		    hdr->flags |= TAC_PLUS_UNENCRYPTED;
		return(0);
	    }
	    if (debug & DEBUG_XOR_FLAG) {
		report(LOG_DEBUG,
		       "data[%d] = 0x%x, xor'ed with hash[%d] = 0x%x -> 0x%x\n",
		       i + j,
		       data[i + j],
		       j,
		       hash[j],
		       data[i + j] ^ hash[j]);
	    }			/* debug */
	    data[i + j] ^= hash[j];
	}
    }
    if (hdr->flags & TAC_PLUS_UNENCRYPTED)
	hdr->flags &= ~TAC_PLUS_UNENCRYPTED;
    else
	hdr->flags |= TAC_PLUS_UNENCRYPTED;
    return(0);
}
