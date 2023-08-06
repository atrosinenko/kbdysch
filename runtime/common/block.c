#include "kbdysch/block.h"

#include "kbdysch/internal-defs.h"
#include "kbdysch/invoker-utils.h"
#include "kbdysch/mutator-interface.h"

#include <fcntl.h>

DEBUG_STRINGS(part_types, "Partition types", FSTYPE_LEN, MAX_PART_COUNT)
DEBUG_COUNTERS(mark_detected,      "Mark detected",                MAX_PART_COUNT)
DEBUG_COUNTERS(mark_not_detected,  "Mark not detected",            MAX_PART_COUNT)
DEBUG_COUNTERS(mark_detected_fail, "Mark detected (failed later)", MAX_PART_COUNT)

const uint8_t MARKER[4] = {'M', 'A', 'R', 'K'};

enum {
  SECTOR_RAW,
  SECTOR_BYTE_FILLED,
};

struct sector_state {
  uint8_t mode;
  uint8_t fill;
};

void kbdysch_fill_pattern(uint8_t *sector_data, uint8_t fill_byte) {
  memset(sector_data, fill_byte, BLK_SECTOR_SIZE);
  memcpy(sector_data, &MARKER, sizeof(MARKER)); // Overwrites the first bytes
}

// FIXME Quick hack: using a "__san" substring makes AFL++ not instrument this function
__attribute__((noinline))
static bool u32_filled_with_byte__san(void *ptr, size_t size, uint8_t byte) {
  CHECK_THAT(((uintptr_t)ptr) % 4 == 0);
  CHECK_THAT(size % 4 == 0);

  uint32_t pattern = byte;
  pattern |= pattern << 8;
  pattern |= pattern << 16;

  uint32_t *array = (uint32_t *)ptr;
  for (unsigned i = 0; i < size / 4; ++i) {
    if (array[i] != pattern)
      return false;
  }
  return true;
}

static struct sector_state detect_pattern(uint8_t *sector_data, unsigned blk_index) {
  struct sector_state result = { SECTOR_RAW, 0 };

  if (memcmp(sector_data, MARKER, sizeof(MARKER))) {
    INCREMENT_DEBUG_COUNTER(mark_not_detected, blk_index, 1);
    return result;
  }

  uint8_t *remainder = &sector_data[sizeof(MARKER)];
  if (u32_filled_with_byte__san(remainder, BLK_SECTOR_SIZE - sizeof(MARKER), remainder[0])) {
    INCREMENT_DEBUG_COUNTER(mark_detected, blk_index, 1);
    result.mode = SECTOR_BYTE_FILLED;
    result.fill = remainder[0];
    return result;
  }

  INCREMENT_DEBUG_COUNTER(mark_detected_fail, blk_index, 1);
  return result;
}

typedef void (*kbdysch_blk_op)(struct kbdysch_block_dev *blk, uint8_t *data,
                              unsigned num_sectors, unsigned offset_sectors);

static void kbdysch_blk_dummy(struct kbdysch_block_dev *blk, uint8_t *data,
                              unsigned num_sectors, unsigned offset_sectors) {
  // do nothing
}

static void kbdysch_blk_read(struct kbdysch_block_dev *blk, uint8_t *data,
                             unsigned num_sectors, unsigned offset_sectors) {
  for (unsigned i = 0; i < num_sectors; ++i) {
    unsigned cur_sector = offset_sectors + i;
    uint8_t *cur_data = &data[i * BLK_SECTOR_SIZE];

    switch (blk->states[cur_sector].mode) {
    case SECTOR_RAW:
      memcpy(cur_data,
             &blk->data[cur_sector * BLK_SECTOR_SIZE],
             BLK_SECTOR_SIZE);
      break;
    case SECTOR_BYTE_FILLED:
      kbdysch_fill_pattern(cur_data, blk->states[cur_sector].fill);
      break;
    default:
      abort();
    }
  }
}

static void kbdysch_blk_write(struct kbdysch_block_dev *blk, uint8_t *data,
                              unsigned num_sectors, unsigned offset_sectors) {
  for (unsigned i = 0; i < num_sectors; ++i) {
    unsigned cur_sector = offset_sectors + i;
    uint8_t *cur_data = &data[i * BLK_SECTOR_SIZE];

    blk->states[cur_sector] = detect_pattern(cur_data, blk->kbdysch_disk_index);
    if (blk->states[cur_sector].mode == SECTOR_RAW) {
      memcpy(&blk->data[cur_sector * BLK_SECTOR_SIZE],
             cur_data,
             BLK_SECTOR_SIZE);
    }
  }
}

void kbdysch_blk_ensure_raw(struct kbdysch_block_dev *blk,
                            unsigned sector_index) {
  uint8_t *sector_start = &blk->data[sector_index * BLK_SECTOR_SIZE];
  struct sector_state *sector_state = &blk->states[sector_index];

  switch (sector_state->mode) {
  case SECTOR_RAW:
    break;
  case SECTOR_BYTE_FILLED:
    kbdysch_fill_pattern(sector_start, sector_state->fill);
    sector_state->mode = SECTOR_RAW;
    break;
  default:
    abort();
  }
}

static void set_part_to_disk(struct lkl_disk *disk, struct kbdysch_block_dev *blk) {
  disk->handle = blk;
}

static struct kbdysch_block_dev *block_dev_from_disk(struct lkl_disk disk) {
  return (struct kbdysch_block_dev *)disk.handle;
}

void blockdev_assign_data(struct kbdysch_block_dev *blk, uint8_t *data, size_t size) {
  CHECK_THAT(size % BLK_SECTOR_SIZE == 0);
  set_part_to_disk(&blk->disk, blk);

  unsigned num_sectors = size / BLK_SECTOR_SIZE;
  blk->data = data;
  blk->states = calloc(num_sectors, sizeof(struct sector_state));
  blk->num_sectors = num_sectors;
}

void blockdev_init_after_boot(struct fuzzer_state *state) {
  int part_count = state->constant_state.part_count;
  RESIZE_DEBUG_VARIABLE(part_types, part_count);
  RESIZE_DEBUG_VARIABLE(mark_detected, part_count);
  RESIZE_DEBUG_VARIABLE(mark_not_detected, part_count);
  RESIZE_DEBUG_VARIABLE(mark_detected_fail, part_count);
  for (int i = 0; i < part_count; ++i) {
    // Create device file for each disk
    if (!state->partitions[i].blockdev.data)
      continue;
    char device_name[128], sysfs_name[128];
    sprintf(device_name, "block-%d-%s", i, state->partitions[i].fstype);
    sprintf(sysfs_name, "block/vd%c", 'a' + i);
    int fd = kernel_open_device_by_sysfs_name(state, device_name, sysfs_name, S_IFBLK);
    INVOKE_SYSCALL(state, close, fd);

    if (part_types) {
      memcpy(mutator_variable_get_ptr(part_types, i),
             state->partitions[i].fstype,
             FSTYPE_LEN);
    }
  }
}

static void update_access_history(struct kbdysch_block_dev *blk,
                                  size_t offset, size_t length) {
  blk->off_start[blk->off_cur] = offset;
  blk->off_end  [blk->off_cur] = offset + length;
  blk->off_cur++;
  if (blk->off_cur >= ACCESS_HISTORY_LEN)
    blk->off_cur = 0;
  blk->access_count++;
}

void blockdev_patch_one_word(struct fuzzer_state *state, struct kbdysch_block_dev *blk) {
  const unsigned param1 = res_get_u16(state) % blk->access_count;
  const int access_nr = ((blk->off_cur - (int)param1) % ACCESS_HISTORY_LEN + ACCESS_HISTORY_LEN) % ACCESS_HISTORY_LEN;

  const unsigned char op = res_get_u8(state);
  const int32_t arg = res_get_u32(state);
  const int patch_size = (op & 0x70) >> 4;
  const int patch_local_range = blk->off_end[access_nr] - blk->off_start[access_nr] - patch_size + 1;

  if (patch_local_range <= 0)
    return;

  const int32_t param2 = res_get_u32(state);
  const int patch_local_offset = (param2 > 0) ? (param2 % patch_local_range) : (param2 % patch_local_range + patch_local_range);
  size_t partition_offset = blk->off_start[access_nr] + patch_local_offset;

  // TODO Handle crossing sector boundaries
  kbdysch_blk_ensure_raw(blk, partition_offset / BLK_SECTOR_SIZE);
  void *patch_destination = blk->data + partition_offset;

  uint64_t original_data, patched_data;
  memcpy(&original_data, patch_destination, patch_size);
  patched_data = original_data;

  switch(op & 0x07) {
  case 0:
  case 1:
    patched_data += (int64_t)arg;
    break;
  case 2:
  case 3:
    patched_data = (int64_t)arg;
    break;
  case 4:
    patched_data &= arg;
    break;
  case 5:
    patched_data |= arg;
    break;
  case 6:
  case 7:
    patched_data ^= arg;
    break;
  }
  memcpy(patch_destination, &patched_data, patch_size);

  TRACE(state, "Patching at 0x%zx, size = %d: 0x%lx -> 0x%lx (op = 0x%02x, arg = 0x%x)",
        partition_offset, patch_size,
        original_data, patched_data,
        op & 0xff, arg);
}

#ifdef USE_LKL
#include "lkl_host.h"

static int mem_get_capacity(struct lkl_disk disk, unsigned long long *res) {
  unsigned num_sectors = block_dev_from_disk(disk)->num_sectors;
  *res = num_sectors * BLK_SECTOR_SIZE;
  return LKL_DEV_BLK_STATUS_OK;
}

static int mem_request(struct lkl_disk disk, struct lkl_blk_req *req) {
  struct kbdysch_block_dev *blk = block_dev_from_disk(disk);
  int disk_index = blk->kbdysch_disk_index;
  kbdysch_blk_op op_handler;

  switch(req->type) {
    case LKL_DEV_BLK_TYPE_READ:
      op_handler = kbdysch_blk_read;
      break;
    case LKL_DEV_BLK_TYPE_WRITE:
      op_handler = kbdysch_blk_write;
      break;
    case LKL_DEV_BLK_TYPE_FLUSH:
    case LKL_DEV_BLK_TYPE_FLUSH_OUT:
      op_handler = kbdysch_blk_dummy;
      return LKL_DEV_BLK_STATUS_OK;
    default:
      // TODO Support TRIM
      return LKL_DEV_BLK_STATUS_UNSUP;
  }

  const unsigned total_sectors = blk->num_sectors;
  if (req->sector >= total_sectors)
      return LKL_DEV_BLK_STATUS_IOERR;

  size_t cur_sector = req->sector;
  for (int i = 0; i < req->count; ++i) {
    // Process single iovec entry
    uint8_t *req_ptr = req->buf[i].iov_base;
    size_t length = req->buf[i].iov_len;
    CHECK_THAT(length % 512 == 0);
    if (cur_sector + length / 512 > total_sectors)
      return LKL_DEV_BLK_STATUS_IOERR;

    update_access_history(blk, cur_sector * 512, length);
    op_handler(blk, req_ptr, length / 512, cur_sector);

    cur_sector += length / 512;
  }
  return LKL_DEV_BLK_STATUS_OK;
}

struct lkl_dev_blk_ops kbdysch_blk_ops = {
  .get_capacity = mem_get_capacity,
  .request = mem_request,
};

#endif
