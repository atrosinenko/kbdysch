#include "kbdysch.h"

#include <syscall.h>
#include <linux/bpf.h>

// A hack for older header version
#ifndef BPF_JMP32
#define BPF_JMP32 6
#endif

#include <pth.h>

#define INPUT_LEN (1 << 16)
#define BPF_LOG_BUF_LEN (1 << 16)

static inline void zero_fill_after__helper(void *variable, void *field,
                                           size_t var_size, size_t field_size) {
  uintptr_t field_offset = (uintptr_t)field - (uintptr_t)variable;
  size_t fill_size = var_size - field_offset - field_size;
  void *fill_start = (void *)((uintptr_t)field + field_size);
  memset(fill_start, 0, fill_size);
}
#define ZERO_FILL_AFTER(variable, field) \
  zero_fill_after__helper(&variable, &variable.field, \
                          sizeof(variable), sizeof(variable.field))

DECLARE_BOOL_KNOB(as_root, "AS_ROOT")
DECLARE_BOOL_KNOB(do_dump, "DUMP")
DECLARE_BOOL_KNOB(force_drop_back_jumps, "NO_BACK_JUMPS")
DECLARE_INT_KNOB(bpf_log_level, "BPF_LOG_LEVEL")

static ALIGNED_ENOUGH unsigned char input_buf[INPUT_LEN];
static char bpf_log_buf[BPF_LOG_BUF_LEN];

static ALIGNED_ENOUGH char data_in[1024];
static ALIGNED_ENOUGH char data_out[1024];

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

    const int dest_pc = i + 1 + insns[i].off;
    if (dest_pc < 0 || dest_pc >= (int)length)
      insns[i].off = 0;
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
  else if (force_drop_back_jumps || (control & 0x30) == 0)
    adjust_jmp(insns, insn_count, /* no_back_jumps = */ true);
  else if ((control & 0x10) == 0)
    adjust_jmp(insns, insn_count, /* no_back_jumps = */ false);

  return insn_count;
}

static void trigger_lazy_initialization(struct fuzzer_state *state) {
  // BTF, etc.
  struct bpf_insn ret0[] = {
    { .code = 0xb7, }, // r0 = 0
    { .code = 0x95, }, // exit
  };
  union bpf_attr load_attr = {
    .prog_type = BPF_PROG_TYPE_SOCKET_FILTER,
    .insn_cnt  = 2,
    .insns     = (uint64_t) ret0,
    .license   = (uint64_t) "GPL",
    .log_level = 7,
    .log_size  = BPF_LOG_BUF_LEN,
    .log_buf   = (uint64_t) bpf_log_buf,
  };
  ZERO_FILL_AFTER(load_attr, log_buf);
  int bpffd = INVOKE_SYSCALL(state, bpf, BPF_PROG_LOAD, (long)&load_attr, sizeof(load_attr));
  fprintf(stderr, "%s\n", bpf_log_buf);
  CHECK_THAT(bpffd >= 0);
  INVOKE_SYSCALL(state, close, bpffd);
  bpf_log_buf[0] = '\0';
}

int main(int argc, const char *argv[])
{
  show_help_and_exit_if_needed(
        argc, argv,
        USAGE_RUN_NATIVELY
        USAGE_LKL_SIMPLE
        );

  struct fuzzer_state *state = create_state(argc, argv, NULL);

  if (!is_native_invoker(state)) {
    kernel_boot(state, argv[1]);
  }

  trigger_lazy_initialization(state);

  if (!as_root)
    CHECK_THAT(INVOKE_SYSCALL(state, setreuid, 0L, 1L) == 0);

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

  union bpf_attr load_attr = {
    .prog_type = BPF_PROG_TYPE_SOCKET_FILTER,
    .insn_cnt  = insn_count,
    .insns     = (uint64_t) input_buf,
    .license   = (uint64_t) "GPL",
    .log_level = (uint32_t) bpf_log_level,
    .log_size  = bpf_log_level ? BPF_LOG_BUF_LEN : 0,
    .log_buf   = (uint64_t) (bpf_log_level ? bpf_log_buf : 0),
  };
  ZERO_FILL_AFTER(load_attr, log_buf);

  if (do_dump)
    dump_to_file("bpf-dump.bin", input_buf, insn_count * 8);

  int bpffd = INVOKE_SYSCALL(state, bpf, BPF_PROG_LOAD, (long)&load_attr, sizeof(load_attr));
  pth_yield(NULL);
  if (bpffd < 0) {
    fprintf(stderr, "Cannot load eBPF program: %s\n%s\n", STRERROR(state, bpffd), bpf_log_buf);
  } else {
    fprintf(stderr, "Program fd = %d, trying to run...\n", bpffd);
    fprintf(stderr, "Restoring EUID = 0...\n");
    CHECK_THAT(INVOKE_SYSCALL(state, setreuid, 0L, 0L) == 0);
    union bpf_attr run_attr = {
      .test.prog_fd       = bpffd,
      .test.data_size_in  = sizeof(data_in),
      .test.data_size_out = sizeof(data_out),
      .test.data_in       = (uint64_t) data_in,
      .test.data_out      = (uint64_t) data_out,
    };
    ZERO_FILL_AFTER(run_attr, test);
    int res = INVOKE_SYSCALL(state, bpf, BPF_PROG_TEST_RUN, (long)&run_attr, sizeof(run_attr));
    fprintf(stderr, "Errno: %s\n", STRERROR(state, res));
  }

  return 0;
}
