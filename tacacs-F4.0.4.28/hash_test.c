// Copyright (c) Facebook, Inc. and its affiliates. All Rights Reserved
#include "tac_plus.h"
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int debug = 0;
int console = 0;
int single = 0;
int inner_loop = 100000;
int outer_loop = 10;

int main (int argc, char **argv) {
  int i, j;
  int counter;
  unsigned int lipaddr;
  struct sockaddr_in sa;
  char memcmd[1024];
  char ip1[INET6_ADDRSTRLEN];
  time_t t;
  client_count_init();

  srand((unsigned) time(&t));
  setvbuf(stdout, NULL, _IONBF, 0);
  snprintf(memcmd, 1024, "cat /proc/%d/statm", getpid());
  printf("CMD: %s\n", memcmd);

  for (i = 0; i < outer_loop; i++) {
    printf ("Loop %d\nMemory: ", i);
    system(memcmd);
    for (j = 1; j <= inner_loop; j++) {
      lipaddr = rand();
      if (rand() % 2) {
        inet_ntop(AF_INET, &lipaddr, ip1, sizeof(ip1));
      } else {
        inet_ntop(AF_INET6, &lipaddr, ip1, sizeof(ip1));
      }
      debug && printf("Increment %s, %d\n", ip1, j);
      counter = increment_client_count_for_proc((pid_t)j, ip1);
      debug && printf("Post Inc Count: %s, %d\n", ip1, counter);
    }
    for (j = inner_loop; j >= 1; j--) {
      debug && printf("Decrement for proc %d\n", j);
      counter = decrement_client_count_for_proc((pid_t)j);
      debug && printf("Post Dec Counter: %d\n", counter);
    }
    dump_client_tables();
  }
  exit(0);
}
