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

#define MARKED_SECTOR_NONE 0x0000
#define MARKED_SECTOR_TYPE_MASK 0xFF00

#define MARKED_SECTOR_TYPE_FILL 0x0100

static void set_part_to_disk(struct lkl_disk *disk, struct kbdysch_block_dev *blk) {
  disk->handle = blk;
}

static struct kbdysch_block_dev *part_from_disk(struct lkl_disk disk) {
  return (struct kbdysch_block_dev *)disk.handle;
}

static bool u32_filled_with_byte(void *ptr, size_t size, uint8_t byte) {
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

static bool detect_marked(int index, uint8_t *data, sector_description *result) {
  if (memcmp(data, MARKER, sizeof(MARKER))) {
    INCREMENT_DEBUG_COUNTER(mark_not_detected, index, 1);
    return false;
  }

  uint8_t *remainder = &data[sizeof(MARKER)];
  if (u32_filled_with_byte(remainder, BLK_SECTOR_SIZE - sizeof(MARKER), remainder[0])) {
    INCREMENT_DEBUG_COUNTER(mark_detected, index, 1);
    *result = MARKED_SECTOR_TYPE_FILL | (unsigned)remainder[0];
    return true;
  }

  INCREMENT_DEBUG_COUNTER(mark_detected_fail, index, 1);
  return false;
}

static bool expand_marked(uint8_t *data, sector_description desc) {
  switch (desc & MARKED_SECTOR_TYPE_MASK) {
  case MARKED_SECTOR_TYPE_FILL:
    memcpy(data, MARKER, sizeof(MARKER));
    memset(data + sizeof(MARKER), desc & 0xff, BLK_SECTOR_SIZE - sizeof(MARKER));
    return true;
  default:
    abort();
  }
}

void blockdev_assign_data(struct kbdysch_block_dev *blk, uint8_t *data, size_t size) {
  set_part_to_disk(&blk->disk, blk);
  blk->size = size;
  blk->data = data;
  blk->sector_state = size == 0 ? NULL : calloc(1 + size / BLK_SECTOR_SIZE, sizeof(blk->sector_state[0]));
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
  *res = part_from_disk(disk)->size;
  return LKL_DEV_BLK_STATUS_OK;
}

static int mem_request(struct lkl_disk disk, struct lkl_blk_req *req) {
  struct kbdysch_block_dev *blk = part_from_disk(disk);
  int disk_index = blk->kbdysch_disk_index;
  bool is_read;
  switch(req->type) {
    case LKL_DEV_BLK_TYPE_READ:
      is_read = true;
      break;
    case LKL_DEV_BLK_TYPE_WRITE:
      is_read = false;
      break;
    case LKL_DEV_BLK_TYPE_FLUSH:
    case LKL_DEV_BLK_TYPE_FLUSH_OUT:
      // no-op
      return LKL_DEV_BLK_STATUS_OK;
    default:
      return LKL_DEV_BLK_STATUS_UNSUP;
  }

  size_t offset = req->sector * 512;

  if (offset >= blk->size)
      return LKL_DEV_BLK_STATUS_IOERR;

  for (int i = 0; i < req->count; ++i) {
    // Process single iovec entry
    uint8_t *req_ptr = req->buf[i].iov_base;
    size_t length = req->buf[i].iov_len;
    if (offset + length > blk->size)
      return LKL_DEV_BLK_STATUS_IOERR;

    update_access_history(blk, offset, length);

    // Split each iovec further, so that each sub-operation
    // never crosses sector boundaries.
    while (length > 0) {
      size_t sector_index = offset / BLK_SECTOR_SIZE;
      size_t sector_offset = offset % BLK_SECTOR_SIZE;
      sector_description *marker_desc = &blk->sector_state[sector_index];
      size_t sub_length = BLK_SECTOR_SIZE - sector_offset; // the remainder of this sector
      if (sub_length > length)
        sub_length = length;
      bool whole_sector = sector_offset == 0 && sub_length == BLK_SECTOR_SIZE;

      uint8_t *cur_part_ptr = &blk->data[offset];
      uint8_t *cur_req_ptr = req_ptr;
      req_ptr += sub_length;
      offset += sub_length;
      length -= sub_length;

      if (whole_sector) {
        sector_description tmp;
        // Try leveraging marked sector representation
        if (is_read && *marker_desc) {
          expand_marked(cur_req_ptr, *marker_desc);
          continue;
        } else if (!is_read && detect_marked(disk_index, cur_req_ptr, &tmp)) {
          *marker_desc = tmp;
          continue;
        } else if (!is_read) {
          // Writing full sector as raw, no need to expand existing mark, if any.
          *marker_desc = MARKED_SECTOR_NONE;
          memcpy(cur_part_ptr, cur_req_ptr, BLK_SECTOR_SIZE);
          continue;
        }
      }

      if (!is_read && *marker_desc) {
        // Partially overwriting marked sector - expand mark first
        expand_marked(cur_part_ptr - sector_offset, *marker_desc);
        *marker_desc = MARKED_SECTOR_NONE;
      }

      CHECK_THAT(*marker_desc == MARKED_SECTOR_NONE);

      if (is_read)
        memcpy(cur_req_ptr, cur_part_ptr, sub_length);
      else
        memcpy(cur_part_ptr, cur_req_ptr, sub_length);
    }
  }
  return LKL_DEV_BLK_STATUS_OK;
}

struct lkl_dev_blk_ops kbdysch_blk_ops = {
  .get_capacity = mem_get_capacity,
  .request = mem_request,
};

#endif
