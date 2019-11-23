#include "kbdysch.h"

#include <syscall.h>
#include <linux/bpf.h>

#define INPUT_LEN (1 << 16)
#define BPF_LOG_BUF_LEN (1 << 16)

static unsigned char input_buf[INPUT_LEN];
static char bpf_log_buf[BPF_LOG_BUF_LEN];

int main(int argc, const char *argv[])
{
  show_help_and_exit_if_needed(
        argc, argv,
        USAGE_RUN_NATIVELY
        USAGE_LKL_SIMPLE
        );

  struct fuzzer_state *state = create_state(argc, argv);
  const int bpf_log_level = get_int_knob("BPF_LOG_LEVEL", 0);

  if (!is_native_invoker(state)) {
    kernel_boot(state, argv[1]);
  }

  union bpf_attr attr;

  attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
  attr.license   = (uint64_t) "GPL";
  attr.log_level = (uint32_t) bpf_log_level;
  attr.log_buf   = (uint64_t) (bpf_log_level ? bpf_log_buf : 0);
  attr.log_size = bpf_log_level ? BPF_LOG_BUF_LEN : 0;

  start_forksrv();
  ssize_t length = read(STDIN_FILENO, input_buf, INPUT_LEN);
  if (length == -1) {
    perror("Cannot read stdin");
    abort();
  }
  attr.insn_cnt = length / 8;
  attr.insns    = (uint64_t) input_buf;

  int bpffd = INVOKE_SYSCALL(state, bpf, BPF_PROG_LOAD, (long)&attr, sizeof(attr));
  if (bpffd < 0) {
    fprintf(stderr, "Cannot load eBPF program: %s\n%s\n", STRERROR(state, bpffd), bpf_log_buf);
  }

  return 0;
}
