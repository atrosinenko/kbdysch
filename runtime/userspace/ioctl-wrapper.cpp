#include "kbdysch/userspace/ioctl-wrapper.h"

#include "kbdysch/kbdysch.h"

namespace kbdysch {

ioctl_wrapper::ioctl_wrapper(struct fuzzer_state *state, int fd)
  : State(state), FD(fd) {}


void ioctl_wrapper::invoke(unsigned long request, void *argp) {
  CHECKED_SYSCALL(State, ioctl, FD, (long)request, (long)argp);
}

int ioctl_wrapper::invoke_unchecked(unsigned long request, void *argp) {
  return INVOKE_SYSCALL(State, ioctl, FD, (long)request, (long)argp);
}

} // namespace kbdysch
