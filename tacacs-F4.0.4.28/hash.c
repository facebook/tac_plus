/*
 * $Id: hash.c,v 1.5 2006-12-13 01:11:37 heas Exp $
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
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

struct entry {
    char *name;
    void *hash;
};
typedef struct entry ENTRY;

/* djb hashing function */
static unsigned long
calculate_hash(char *name)
{
  unsigned long hash = 5381;
  int c;

  while (c = *name++)
    hash = ((hash >> 5) + hash) + c; /* hash * 33 + c */
  return hash;
}

/* Lookup a name in a hash table.  Return its node if it exists, else NULL */
void *
hash_lookup(void **hashtab, char *name)
{
    ENTRY *entry;
    unsigned long hashval = calculate_hash(name);
    int hashslot = hashval % HASH_TAB_SIZE;
    entry = hashtab[hashslot];

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
    unsigned long hashval;
    int hashslot;

    entry = hash_lookup(hashtab, newentry->name);
    if (entry)
      return(entry);

    /* Node does not exist in table. Add it */
    hashval = calculate_hash(newentry->name);
    hashslot = hashval % HASH_TAB_SIZE;
    newentry->hash = hashtab[hashslot];
    hashtab[hashslot] = newentry;
    return(NULL);
}

void * hash_delete_entry(void **hashtab, char *entry_name) {
  ENTRY *entry;
  ENTRY *tentry;
  unsigned long hashval = calculate_hash(entry_name);
  int hashslot = hashval % HASH_TAB_SIZE;
  struct entry *last_entry = NULL;

  entry = hashtab[hashslot];
  while (entry) {
    if (STREQ(entry_name, entry->name)) {
      if ((last_entry == NULL) && (entry->hash == NULL)) {
        /* the hash slot is empty so we can set it to null */
        hashtab[hashslot] = NULL;
      } else if ((last_entry != NULL) && (entry->hash != NULL)) {
        /* we need to attach the previous entry to the next one
         * so we can remove this one */
        last_entry->hash = entry->hash;
      } else if (last_entry == NULL) {
        /* first entry so we need to advance the hash slot to the next one*/
        hashtab[hashslot] = entry->hash;
      } else if (entry->hash == NULL) {
        /* last entry in bucket so we need to null the next pointer in the previous entry */
        last_entry->hash = NULL;
      }
      entry->hash = NULL;
      return entry;
    }
    last_entry = entry;
    entry = entry->hash;
  }
  /* we didn't find the entry */
  return NULL;
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
