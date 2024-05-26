#include "kbdysch/userspace/btrfs.h"

#include "kbdysch/input.h"
#include "kbdysch/internal-defs.h"
#include "kbdysch/userspace/ioctl-wrapper.h"

#include <fcntl.h>
#include <linux/btrfs.h>

#include <string>

using namespace kbdysch;

static void btrfs_invoke_defrag(
    struct fuzzer_state *state,
    input_wrapper &input,
    partition_t *partition) {
  struct btrfs_ioctl_defrag_range_args args = {};

  unsigned arg1 = input.next_bits<4>();

  args.start = input.next_bits<8>() << 16;
  args.start |= input.next_bits<8>();

  args.len = input.next_bits<8>() << 16;
  args.len |= input.next_bits<8>();

  args.flags = arg1;

  args.extent_thresh = input.next_bits<4>() << 8;
  args.extent_thresh |= input.next_bits<4>();

  args.compress_type = input.next_bits<4>();

  TRACE(state,
        "Invoking Btrfs defrag: %#llx+%#llx, flags %#llx, "
        "ext. threshold %#lx, compress %#lx",
        LLU(args.start), LLU(args.len), LLU(args.flags),
        LU(args.extent_thresh), LU(args.compress_type));
  std::string mount_point = partition->mount_point;
  for (unsigned i = 0; i < state->current_state.file_name_count; ++i) {
    std::string file_name = mount_point + "/" + state->mutable_state.file_names[i];
    int fd = INVOKE_SYSCALL(state, openat, AT_FDCWD, (long)file_name.c_str(), O_RDONLY);
    if (fd < 0)
      continue;

    ioctl_wrapper ioctl(state, fd);
    int res = ioctl.invoke_unchecked(BTRFS_IOC_DEFRAG_RANGE, &args);
    if (res < 0) {
      TRACE(state, "Error: %s", LKL_STRERROR(res));
      CHECK_THAT(res == -EPERM || res == -ENOTSUP || res == -EINVAL || res == -ENOSPC);
    }
    INVOKE_SYSCALL(state, close, fd);
  }

  INVOKE_SYSCALL_0(state, sync);
}

void kbdysch_btrfs_maintainance(struct fuzzer_state *state, int part_idx) {
  partition_t *part = &state->partitions[part_idx];
  input_wrapper input(state);
  input.reserve_bytes(8);
  unsigned op = input.next_bits<4>();
  btrfs_invoke_defrag(state, input, part);
}
