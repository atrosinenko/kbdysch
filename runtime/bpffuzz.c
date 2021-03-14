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

static inline bool is_exit(unsigned opcode) {
  return opcode == 0x95;
}

static void clear_unused_fields(struct bpf_insn insns[], size_t length) {
  for (unsigned i = 0; i < length; ++i) {
    switch (BPF_CLASS(insns[i].code)) {
    case BPF_ALU:
    case BPF_ALU64:
      insns[i].off = 0;
      // fall-through
    case BPF_JMP32:
    case BPF_JMP: {
      const bool is_immediate = (insns[i].code & 0x08) == 0;
      if (is_immediate)
        insns[i].src_reg = 0;
      else
        insns[i].imm = 0;
      break;
    }
    case BPF_LD:
      insns[i].off = 0;
    case BPF_ST:
      insns[i].src_reg = 0;
    case BPF_LDX:
    case BPF_STX:
      insns[i].imm = 0;
    default:
      break;
    }
  }
}

static void fix_registers(struct bpf_insn insns[], size_t length) {
  for (unsigned i = 0; i < length; ++i) {
    if (insns[i].src_reg > 10)
      insns[i].src_reg = 0;
    if (insns[i].dst_reg > 10)
      insns[i].dst_reg = 0;
  }
}

static size_t drop_branches(struct bpf_insn insns[], size_t length) {
  size_t new_length = 0;
  for (unsigned i = 0; i < length; ++i) {
    const unsigned opcode = insns[i].code;
    const unsigned cls = BPF_CLASS(opcode);
    const bool has_jmp_class = cls == BPF_JMP || cls == BPF_JMP32;
    if (!has_jmp_class || is_exit(opcode))
      insns[new_length++] = insns[i];
  }
  return new_length;
}

static void adjust_jmp(struct bpf_insn insns[], size_t length,
                       bool no_back_jumps) {
  for (unsigned i = 0; i < length; ++i) {
    const unsigned opcode = insns[i].code;
    const unsigned cls = BPF_CLASS(opcode);
    const bool has_jmp_class = cls == BPF_JMP || cls == BPF_JMP32;
    if (!has_jmp_class)
      continue;

    if (is_exit(opcode)) {
      // leave 'exit' opcode as-is, set other fields to zero
      insns[i] = (struct bpf_insn){ .code = 0x95 };
      continue;
    }

    if (no_back_jumps && insns[i].off < 0)
      insns[i].off = 0;

    const int pc = i + 1;
    while (pc + insns[i].off < 0)
      insns[i].off >>= 1;
    while (pc + insns[i].off >= (int)length)
      insns[i].off >>= 1;
  }
}

static size_t preprocess_program(struct bpf_insn insns[], size_t insn_count,
                                 uint64_t control) {
  // Try various independent fixups.
  if ((control & 0x01) == 0) {
    // Append an exit instruction
    insns[insn_count++] = (struct bpf_insn) { .code = 0x95 };
  }
  if ((control & 0x02) == 0)
    clear_unused_fields(insns, insn_count);
  if ((control & 0x04) == 0)
    fix_registers(insns, insn_count);

  // Depending on bits [8:4] of `control`, change the control flow more or less
  // conservatively.
  if ((control & 0xf0) == 0)
    insn_count = drop_branches(insns, insn_count);
  else if ((control & 0x30) == 0)
    adjust_jmp(insns, insn_count, /* no_back_jumps = */ true);
  else if ((control & 0x10) == 0)
    adjust_jmp(insns, insn_count, /* no_back_jumps = */ false);

  return insn_count;
}

int main(int argc, const char *argv[])
{
  show_help_and_exit_if_needed(
        argc, argv,
        USAGE_RUN_NATIVELY
        USAGE_LKL_SIMPLE
        );

  struct fuzzer_state *state = create_state(argc, argv, NULL);
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

  const ssize_t length = read(STDIN_FILENO, input_buf, INPUT_LEN);
  if (length == -1) {
    perror("Cannot read stdin");
    abort();
  }

  const int extra_bytes = length % 8;
  uint64_t control = 0;
  memcpy(&control, input_buf + length - extra_bytes, extra_bytes);
  fprintf(stderr, "Loaded %zd bytes, with %d control bytes: 0x%016llx.\n",
          length, extra_bytes, (long long) control);

  const size_t insn_count = preprocess_program(
        (struct bpf_insn*)input_buf, length / 8, control);
  attr.insn_cnt = insn_count;
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
