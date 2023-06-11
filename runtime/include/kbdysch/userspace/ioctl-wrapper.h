#ifndef KBDYSCH_USERSPACE_IOCTL_WRAPPER_H
#define KBDYSCH_USERSPACE_IOCTL_WRAPPER_H

struct fuzzer_state;

namespace kbdysch {

class ioctl_wrapper {
public:
  ioctl_wrapper(struct fuzzer_state *state, int fd);

  void invoke(unsigned long request, void *argp);
  int invoke_unchecked(unsigned long request, void *argp);

private:
  struct fuzzer_state *State;
  int FD;
};

} // namespace kbdysch

#endif // KBDYSCH_USERSPACE_IOCTL_WRAPPER_H
