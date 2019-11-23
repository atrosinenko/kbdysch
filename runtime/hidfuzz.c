#include "kbdysch.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stddef.h>

#include <linux/uhid.h>

#include <pth.h>

volatile static union {
  struct uhid_event evt;
  uint8_t raw[sizeof (struct uhid_event)];
} input_data;

int main(int argc, const char *argv[])
{
  show_help_and_exit_if_needed(
        argc, argv,
        USAGE_RUN_NATIVELY
        USAGE_LKL_SIMPLE);

  struct fuzzer_state *state = create_state(argc, argv);

  kernel_configure_diskless(state);
  if (is_native_invoker(state)) {
    kernel_boot(state, argv[1]);
  }
  int uhid_fd   = kernel_open_char_dev_by_sysfs_name(state, "uhid",   "misc/uhid");
  int event0_fd = kernel_open_char_dev_by_sysfs_name(state, "event0", "input/event0");
  INVOKE_SYSCALL(state, close, event0_fd);

  pth_yield(NULL);

  input_data.evt.type = UHID_CREATE2;
  input_data.evt.u.create2.name[0] = 'a';
  input_data.evt.u.create2.phys[0] = 'b';
  input_data.evt.u.create2.uniq[0] = 'c';

  start_forksrv();

  const int offset = offsetof(struct uhid_event, u.create2.rd_size);
  int read_size = read(0, input_data.raw + offset, sizeof(input_data) - offset);
  fprintf(stderr, "%d bytes read.\n", read_size);
  int res = INVOKE_SYSCALL(state, write, uhid_fd, (long)&input_data, sizeof(struct uhid_event));
  if (res < 0) {
    fprintf(stderr, "res = %s\n", STRERROR(state, res));
    exit(1);
  }

  return 0;
}
