/*
 * $Id: hash.c,v 1.5 2006-12-13 01:11:37 heas Exp $
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

struct entry {
    char *name;
    void *hash;
};
typedef struct entry ENTRY;

static int calculate_hash(char *);

/* Calculate hash value from a string */
static int
calculate_hash(char *name)
{
    int i;
    int len = strlen(name);
    int hashval = 0;

    for (i = 0; i < len; i++) {
	hashval += name[i] * (i + 1);
    }
    hashval += name[0];
    hashval = hashval > 0 ? hashval : -hashval;
    return(hashval);
}

/* Lookup a name in a hash table.  Return its node if it exists, else NULL */
void *
hash_lookup(void **hashtab, char *name)
{
    ENTRY *entry;
    int hashval = calculate_hash(name);

    entry = hashtab[hashval % HASH_TAB_SIZE];

    while (entry) {
	if (STREQ(name, entry->name))
	    /* Node exists in table. return it */
	    return(entry);
	entry = entry->hash;
    }
    return(NULL);
}

/* Add a node to a hash table.  Return node if it exists, NULL otherwise */
void *
hash_add_entry(void **hashtab, struct entry *newentry)
{
    ENTRY *entry;
    int hashval;

    entry = hash_lookup(hashtab, newentry->name);
    if (entry)
	return(entry);

    /* Node does not exist in table. Add it */
    hashval = calculate_hash(newentry->name);
    newentry->hash = hashtab[hashval % HASH_TAB_SIZE];
    hashtab[hashval % HASH_TAB_SIZE] = newentry;
    return(NULL);
}

/* Return an array of pointers to all the entries in a hash table */
void **
hash_get_entries(void **hashtab)
{
    int i;
    int cnt;
    ENTRY *entry;
    void **entries, **p;
    int n, longest;

    longest = 0;
    cnt = 0;
    for (i = 0; i < HASH_TAB_SIZE; i++) {
	entry = hashtab[i];
	n = 0;
	while (entry) {
	    cnt++;
	    n++;
	    entry = entry->hash;
	}
	if (n > longest)
	    longest = n;
    }
    cnt++;			/* Add space for NULL entry at end */

    p = entries = (void **) tac_malloc(cnt * sizeof(void *));
    for (i = 0; i < HASH_TAB_SIZE; i++) {
	entry = hashtab[i];
	while (entry) {
	    *p++ = entry;
	    entry = entry->hash;
	}
    }
    *p++ = NULL;
    return(entries);
}
