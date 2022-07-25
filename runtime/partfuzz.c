#include "kbdysch/kbdysch.h"
#include "kbdysch/invoker-utils.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <linux/loop.h>

#define LOOP_BACKING_STORAGE "/loop-data"

static uint8_t disk_contents[1 << 20];

int main(int argc, const char *argv[])
{
  int res;
  struct fuzzer_state * const state = create_state(argc, argv, NULL);

  show_help_and_exit_if_needed(
        argc, argv,
        USAGE_LKL_SIMPLE);

  if (is_native_invoker(state)) {
    fprintf(stderr, "Native mode is not yet supported.\n");
    exit(1);
  }
  if (argc < 2) {
    fprintf(stderr, "Too few agruments specified.\n");
    exit(1);
  }

  kernel_configure_diskless(state, "/");
  kernel_boot(state, argv[1]);

  int loop_fd = kernel_open_device_by_sysfs_name(state, "loop0", "block/loop0", S_IFBLK);
  int file_fd = INVOKE_SYSCALL(state, openat, AT_FDCWD, (long)LOOP_BACKING_STORAGE, O_RDWR | O_CREAT, 0600);
  CHECK_THAT(file_fd >= 0);

  start_forksrv();
  ssize_t length = read(0, disk_contents, sizeof(disk_contents));
  CHECK_THAT(length >= 0);

  // round up to 4k block
  length = (length + 4095) & ~4095;

  res = INVOKE_SYSCALL(state, write, file_fd, (intptr_t)disk_contents, length);
  CHECK_THAT(res == length);
  res = INVOKE_SYSCALL(state, ioctl, loop_fd, LOOP_SET_FD, file_fd);
  CHECK_THAT(res == 0);

  struct loop_info64 info;
  memset(&info, 0, sizeof(info));
  info.lo_flags = LO_FLAGS_PARTSCAN;
  strncpy((char *)info.lo_file_name, LOOP_BACKING_STORAGE, LO_NAME_SIZE);
  res = INVOKE_SYSCALL(state, ioctl, loop_fd, LOOP_SET_STATUS64, (intptr_t)&info);
  fprintf(stderr, "ioctl: %s\n", STRERROR(state, res));

  return 0;
}
