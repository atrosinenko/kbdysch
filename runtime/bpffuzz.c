#include "kbdysch.h"

#include <syscall.h>
#include <linux/bpf.h>

#include <pth.h>

#define INPUT_LEN (1 << 16)
#define BPF_LOG_BUF_LEN (1 << 16)

static unsigned char input_buf[INPUT_LEN];
static char bpf_log_buf[BPF_LOG_BUF_LEN];

static char data_in[1024];
static char data_out[1024];

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
  memset(&attr, 0, sizeof(attr));

  attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
  attr.license   = (uint64_t) "GPL";
  attr.log_level = (uint32_t) bpf_log_level;
  attr.log_buf   = (uint64_t) (bpf_log_level ? bpf_log_buf : 0);
  attr.log_size = bpf_log_level ? BPF_LOG_BUF_LEN : 0;

  if (!get_bool_knob("AS_ROOT", 0)) {
    CHECK_THAT(INVOKE_SYSCALL(state, setreuid, 0L, 1L) == 0);
  }

  start_forksrv();
  ssize_t length = read(STDIN_FILENO, input_buf, INPUT_LEN);
  if (length == -1) {
    perror("Cannot read stdin");
    abort();
  }
  attr.insn_cnt = length / 8;
  attr.insns    = (uint64_t) input_buf;

  int bpffd = INVOKE_SYSCALL(state, bpf, BPF_PROG_LOAD, (long)&attr, sizeof(attr));
  pth_yield(NULL);
  if (bpffd < 0) {
    fprintf(stderr, "Cannot load eBPF program: %s\n%s\n", STRERROR(state, bpffd), bpf_log_buf);
  } else {
    fprintf(stderr, "Program fd = %d, trying to run...\n", bpffd);
    fprintf(stderr, "Restoring EUID = 0...\n");
    CHECK_THAT(INVOKE_SYSCALL(state, setreuid, 0L, 0L) == 0);
    memset(&attr, 0, sizeof(attr));
    attr.test.prog_fd = bpffd;
    attr.test.data_in       = (uint64_t) data_in;
    attr.test.data_size_in  = sizeof(data_in);
    attr.test.data_out      = (uint64_t) data_out;
    attr.test.data_size_out = sizeof(data_out);
    int res = INVOKE_SYSCALL(state, bpf, BPF_PROG_TEST_RUN, (long)&attr, sizeof(attr));
    fprintf(stderr, "Errno: %s\n", STRERROR(state, res));
  }

  return 0;
}
