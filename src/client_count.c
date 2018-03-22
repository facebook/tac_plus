#include "tac_plus.h"
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

#define MSGBUFSZ 1024
static char msgbuf[MSGBUFSZ];
static void *client_table[HASH_TAB_SIZE];  /* Table of client declarations */
static void *proc_table[HASH_TAB_SIZE];  /* Table of proc declarations */

/* initialize the client table proc tables
 * The client table stores the number of connections for
 * each client ip.
 * The proc table stores the link between process id and
 * client ip. When a tacacs process dies, the parent only
 * get the process id, so we need to link the two */

void client_count_init(void) {
  memset(proc_table, 0, sizeof(proc_table));
  memset(client_table, 0, sizeof(client_table));
}

void remove_client_entry(char* client_ip)
{
  CLIENT *entry = (CLIENT *)hash_delete_entry(client_table, client_ip);
  if (entry) {
    if (entry->name)
      free(entry->name);
    free(entry);
  }
}

void remove_proc_entry(char* proc_id)
{
  PROC_CLIENT *entry = (PROC_CLIENT *)hash_delete_entry(proc_table, proc_id);
  if (entry) {
    if (entry->name)
      free(entry->name);
    if (entry->client_ip)
      free(entry->client_ip);
    free(entry);
  }
}

/* Map a process id to client IP address */
void create_proc_client_map(pid_t process_id, char* client_ip)
{
  /* max size of a 64bit number is 19 chars */
  char pid_str[20];
  snprintf(pid_str, 20, "%d", process_id);
  PROC_CLIENT *pc = (PROC_CLIENT *)tac_malloc(sizeof(PROC_CLIENT));
  memset(pc, 0, sizeof(PROC_CLIENT));
  pc->name = tac_strdup(pid_str);
  pc->hash = NULL;
  pc->client_ip = tac_strdup(client_ip);
  hash_add_entry(proc_table, (void*)pc);
}

/* delete the mapping between process id and IP address */
void delete_proc_client_map(pid_t process_id)
{
  char pid_str[20];
  snprintf(pid_str, 20, "%d", process_id);
  remove_proc_entry(pid_str);
}

/* get the client count for a given client ip */
int get_client_count(char* client_ip)
{
  int count = 0;
  /* now we see if there is a hash entry for this client_ip
   * returns 0 if the client does not yet exist */
  CLIENT *c = hash_lookup(client_table, client_ip);
  if (c)
    count = c->con_count;

  return count;
}

/* increment the client counter for a client */
int increment_client_count(char* client_ip)
{
  int count = get_client_count(client_ip);
  /* create a new hash entry add it to the hash table */
  CLIENT *nc = (CLIENT *)tac_malloc(sizeof(CLIENT));
  memset(nc, 0, sizeof(CLIENT));
  nc->name = tac_strdup(client_ip);
  nc->hash = NULL;
  nc->con_count = count + 1;
  if (count) {
    /* the hash does not support update, so we need to delete + add */
    remove_client_entry(client_ip);
  }
  hash_add_entry(client_table, (void *)nc);
  return nc->con_count;
}

char * get_client_ip_from_pid(pid_t process_id)
{
  char pid_str[20];
  /* hashing only works in strings, so we convert here */
  snprintf(pid_str, 20, "%d", process_id);
  PROC_CLIENT *pc = hash_lookup(proc_table, pid_str);
  if (pc) {
    return pc->client_ip;
  }
}

/* derement the client counter for a given client IP */
int decrement_client_count(char* client_ip) {
  CLIENT *nc;
  int count = get_client_count(client_ip);
  if (! count) {
    return 0;
  }
  count--;
  if (count >= 1) {
    /* we update the existing hash entry if the count is still positive
     * but the hash does not support update so we have to delete
     * and then add */
    CLIENT *nc = (CLIENT *)tac_malloc(sizeof(CLIENT));
    memset(nc, 0, sizeof(CLIENT));
    nc->name = tac_strdup(client_ip);
    nc->hash = NULL;
    nc->con_count = count;
    remove_client_entry(client_ip);
    hash_add_entry(client_table, (void *)nc);
  } else if (count == 0) {
    /* if it was the last client, we delete the entry */
    remove_client_entry(client_ip);
  }
  return count;
}

int decrement_client_count_for_proc(pid_t process_id)
{
  int proc_count = 0;
  char* client_ip = get_client_ip_from_pid(process_id);
  if (client_ip) {
    proc_count = decrement_client_count(client_ip);
    snprintf(msgbuf, MSGBUFSZ, "Pid %lu Lowered Count for %s to %d",
        process_id, client_ip, proc_count);
    report(LOG_ALERT, msgbuf);
    delete_proc_client_map(process_id);
  } else {
    snprintf(msgbuf, MSGBUFSZ, "Failed to find client ip for pid %lu", process_id);
    report(LOG_ALERT, msgbuf);
  }
  return proc_count;
}


int increment_client_count_for_proc(pid_t process_id, char* client_ip)
{
  /* first we need to map pid to client_ip */
 create_proc_client_map(process_id, client_ip);
  /* now we inrement */
  return increment_client_count(client_ip);
}

void dump_client_tables()
{
  CLIENT *cl;
  PROC_CLIENT *pc;
  CLIENT **clients = (CLIENT **) hash_get_entries(client_table);
  PROC_CLIENT **procs = (PROC_CLIENT **) hash_get_entries(proc_table);
  CLIENT **c;
  PROC_CLIENT **p;

  for (p = procs; *p; p++) {
    pc = *p;
    report(LOG_ALERT, "Proc: %s, IP: %s", pc->name, pc->client_ip);
  }
  for (c = clients; *c; c++) {
    cl = *c;
    report(LOG_ALERT, "Client: %s, Count: %d", cl->name, cl->con_count);
  }
}
