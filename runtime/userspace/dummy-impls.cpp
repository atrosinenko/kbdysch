#include "kbdysch/userspace/btrfs.h"

#include <stdio.h>
#include <stdlib.h>

#ifndef HAS_LINUX_BTRFS_H
static inline void kbdysch_btrfs_maintainance(struct fuzzer_state *state, int part_idx) {
  fprintf(stderr, "Requested MAINTAINANCE operation for Btrfs partition.\n");
  fprintf(stderr, "Either compile kBdysch with Btrfs support or set NO_MAINTAINANCE variable.\n");
  abort();
}
#endif // HAS_LINUX_BTRFS_H
