#include "block.h"
#include "kbdysch.h"

#include "internal-defs.h"
#include "invoker-utils.h"

#include <fcntl.h>

static void set_part_to_disk(struct lkl_disk *disk, struct kbdysch_block_dev *blk) {
  disk->handle = blk;
}

static struct kbdysch_block_dev *part_from_disk(struct lkl_disk disk) {
  return (struct kbdysch_block_dev *)disk.handle;
}

void blockdev_assign_data(struct kbdysch_block_dev *blk, uint8_t *data, size_t size) {
  set_part_to_disk(&blk->disk, blk);
  blk->size = size;
  blk->data = data;
}

void blockdev_init_after_boot(struct fuzzer_state *state) {
  int part_count = state->constant_state.part_count;
  for (int i = 0; i < part_count; ++i) {
    // Create device file for each disk
    char device_name[128], sysfs_name[128];
    sprintf(device_name, "block-%d-%s", i, state->partitions[i].fstype);
    sprintf(sysfs_name, "block/vd%c", 'a' + i);
    int fd = kernel_open_device_by_sysfs_name(state, device_name, sysfs_name, S_IFBLK);
    INVOKE_SYSCALL(state, close, fd);
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

    if (is_read)
      memcpy(req_ptr, &blk->data[offset], length);
    else
      memcpy(&blk->data[offset], req_ptr, length);

    offset += length;
  }
  return LKL_DEV_BLK_STATUS_OK;
}

struct lkl_dev_blk_ops kbdysch_blk_ops = {
  .get_capacity = mem_get_capacity,
  .request = mem_request,
};

#endif
