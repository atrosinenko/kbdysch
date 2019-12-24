#include "kbdysch.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stddef.h>

#include <linux/uhid.h>

#include <pth.h>

struct uhid_event evt;

int main(int argc, const char *argv[])
{
  show_help_and_exit_if_needed(
        argc, argv,
        USAGE_RUN_NATIVELY
        USAGE_LKL_SIMPLE);

  struct fuzzer_state *state = create_state(argc, argv);

  kernel_configure_diskless(state, "/tmp/");
  if (!is_native_invoker(state)) {
    kernel_boot(state, argv[1]);
  }
  int uhid_fd   = kernel_open_char_dev_by_sysfs_name(state, "uhid",   "devices/virtual/misc/uhid");

  pth_yield(NULL);

  evt.type = UHID_CREATE2;
  evt.u.create2.name[0] = 'a';
  evt.u.create2.phys[0] = 'b';
  evt.u.create2.uniq[0] = 'c';

  start_forksrv();

  const int offset = offsetof(struct uhid_event, u.create2.rd_size);
  int read_size = read(0, ((uint8_t *)&evt) + offset, sizeof(evt) - offset);
  // Speed is significant for fuzzing...
  evt.u.create2.rd_size %= 4096;
  fprintf(stderr, "%d bytes read.\n", read_size);
  int res = INVOKE_SYSCALL(state, write, uhid_fd, (long)&evt, sizeof(evt));
  if (res < 0) {
    fprintf(stderr, "res = %s\n", STRERROR(state, res));
    exit(1);
  }
  // Switch to kernel threads so they can process HID descriptor
  pth_yield(NULL);
  pth_yield(NULL);

  return 0;
}
