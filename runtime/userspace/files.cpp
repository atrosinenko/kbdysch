#include "kbdysch/userspace/files.h"

#include "kbdysch/kbdysch.h"

#include <fcntl.h>
#include <string.h>

size_t kernel_read_from_file(struct fuzzer_state *state, const char *filename,
                             const void *data, size_t size) {
  int fd = CHECKED_SYSCALL(state, openat, AT_FDCWD, (long)filename, O_RDONLY, 0);
  ssize_t res = CHECKED_SYSCALL(state, read, fd, (long)data, (long)size);
  INVOKE_SYSCALL(state, close, fd);
  return (size_t)res;
}

void kernel_dump_file_contents(struct fuzzer_state *state, const char *filename) {
  static char contents[64 * 1024];
  size_t length = kernel_read_from_file(state, filename, contents, sizeof(contents) - 1);
  contents[length] = '\0';
  TRACE(state, "=== Contents of %s ===\n%s", filename, contents);
}

void kernel_write_to_file(struct fuzzer_state *state, const char *filename,
                          const void *data, size_t size, int write_may_fail) {
  int fd = CHECKED_SYSCALL(state, openat, AT_FDCWD, (long)filename, O_WRONLY, 0);
  long err = INVOKE_SYSCALL(state, write, fd, (long)data, size);
  if (err < 0)
    WARN(state, "write of %d bytes failed: %d (%s)", size, err, STRERROR(state, err));
  else
    TRACE(state, "OK");
  CHECK_THAT(err == size || write_may_fail);
  INVOKE_SYSCALL(state, close, fd);
}

void kernel_write_string_to_file(struct fuzzer_state *state, const char *filename,
                                 const char *str, int write_may_fail) {
  TRACE_NO_NL(state, "Writing [%s] to %s... ", str, filename);
  kernel_write_to_file(state, filename, str, strlen(str), write_may_fail);
}

void wait_for_fd(struct fuzzer_state *state, int fd, bool for_read, bool for_write) {
  fd_set rfds, wfds;
  fd_set *arg_rfds = NULL, *arg_wfds = NULL;
  if (for_read) {
    FD_ZERO(&rfds);
    FD_SET(fd, &rfds);
    arg_rfds = &rfds;
  }
  if (for_write) {
    FD_ZERO(&wfds);
    FD_SET(fd, &wfds);
    arg_wfds = &wfds;
  }
  int res = INVOKE_SYSCALL(state, pselect6, fd + 1, (long)arg_rfds, (long)arg_wfds, (long)NULL, 0, 0);
  if (res <= 0) {
    LOG_FATAL("pselect6: %s", STRERROR(state, res));
    abort();
  }
}
