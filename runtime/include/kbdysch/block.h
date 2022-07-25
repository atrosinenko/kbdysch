#ifndef KBDYSCH_BLOCK_H
#define KBDYSCH_BLOCK_H

#include <stddef.h>
#include <stdint.h>

#ifdef USE_LKL
#include "lkl.h"
#else
struct lkl_disk {
  /* dummy */
  void *handle;
};
#endif

struct fuzzer_state;

#define ACCESS_HISTORY_LEN 1024
#define BLK_SECTOR_SIZE 512
#define FSTYPE_RAW "raw:"

typedef uint16_t sector_description;

struct kbdysch_block_dev {
  struct lkl_disk disk;   ///< LKL device structure associated with this partition
  int lkl_disk_id;        ///< LKL disk ID associated with this partition
  int kbdysch_disk_index; ///< Index of this disk inside state->partitions in kBdysch

  int off_start[ACCESS_HISTORY_LEN]; ///< Start offset of the recorded access
  int off_end  [ACCESS_HISTORY_LEN]; ///< End offset of the recorded access
  long long access_count; ///< Total number of accesses issued on this partition
  int off_cur; ///< Index of current offset to be recorded (in a circular buffer manner)

  uint8_t *data; ///< Pointer to partition image data
  size_t size;   ///< Size of partition image data in bytes
  sector_description *sector_state; ///< Special sector status information (pattern-filled, etc.)
};

extern const uint8_t MARKER[4];

void blockdev_assign_data(struct kbdysch_block_dev *blk, uint8_t *data, size_t size);
void blockdev_init_after_boot(struct fuzzer_state *state);

void blockdev_patch_one_word(struct fuzzer_state *state, struct kbdysch_block_dev *blk);

#ifdef USE_LKL
extern struct lkl_dev_blk_ops kbdysch_blk_ops;
#endif

#endif // KBDYSCH_BLOCK_H
