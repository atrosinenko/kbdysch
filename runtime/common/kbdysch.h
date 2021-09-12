#ifndef KBDYSCH_H
#define KBDYSCH_H

#include "common-defs.h"
#include "compiler.h"

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <syscall.h> // for SYS_* numbers

#ifdef USE_LKL
#include "lkl.h"
#endif

#define FSTYPE_RAW "raw: "

/// \defgroup usage_help
/// @{

#define USAGE_WITH_ARGS(args_str) "%1$s " args_str "\n"
#define USAGE_THEN_DO(descr_str)  "\t" descr_str "\n"
#define USAGE_RUN_NATIVELY \
    USAGE_WITH_ARGS("native") \
    USAGE_THEN_DO("Apply to host kernel")
#define USAGE_LKL_SIMPLE \
    USAGE_WITH_ARGS("<kernel command line>") \
    USAGE_THEN_DO  ("Run test on Linux Kernel Library")

/**
 * @brief Either continues execution or shows the help message and exits
 * @param argc         `argc` passed to `main()`
 * @param argv         `argv` passed to `main()`
 * @param help_message Help message to show if needed
 */
void show_help_and_exit_if_needed(int argc, const char *argv[], const char *help_message);

/// @}

/// \defgroup knobs Retrieving configuretion parameters
/// @{

typedef uint64_t bitmask_t;
#define BIT(n) ((bitmask_t)1 << (n))
bool get_bool_knob(const char *name, bool default_value);
bitmask_t get_bitmask_knob(const char *name, bitmask_t default_value);
int get_int_knob(const char *name, int default_value);
const char *get_string_knob(const char *name, const char *default_value);

#define DECLARE_KNOB_DEF(type, getter, name, var, default_value) \
  static type name; \
  CONSTRUCTOR(init_##name) { name = getter(var, default_value); }
#define DECLARE_BOOL_KNOB(name, var) \
  DECLARE_KNOB_DEF(bool, get_bool_knob, name, var, false)
#define DECLARE_BITMASK_KNOB(name, var) \
  DECLARE_KNOB_DEF(bitmask_t, get_bitmask_knob, name, var, 0)
#define DECLARE_INT_KNOB_DEF(name, var, default_value) \
  DECLARE_KNOB_DEF(int, get_int_knob, name, var, default_value)
#define DECLARE_INT_KNOB(name, var) \
  DECLARE_KNOB_DEF(int, get_int_knob, name, var, 0)
#define DECLARE_STRING_KNOB(name, var) \
  DECLARE_KNOB_DEF(const char *, get_string_knob, name, var, NULL)

/// @}

void res_add_to_known_strings(struct fuzzer_state *state, const char *string);

void kernel_setup_disk(struct fuzzer_state *state, const char *filename, const char *fstype);
void kernel_configure_diskless(struct fuzzer_state *state, const char *mpoint);
void kernel_boot(struct fuzzer_state *state, const char *cmdline);
size_t kernel_read_from_file(struct fuzzer_state *state, const char *filename, const void *data, size_t size);
void kernel_dump_file_contents(struct fuzzer_state *state, const char *filename);
void kernel_write_to_file(struct fuzzer_state *state, const char *filename, const void *data, size_t size, int write_may_fail);
void kernel_write_string_to_file(struct fuzzer_state *state, const char *filename, const char *str, int write_may_fail);
void kernel_invoke_write_to_file(struct fuzzer_state *state);
int kernel_open_device_by_sysfs_name(struct fuzzer_state *state, const char *name, const char *sysfs_id, int dev_kind);
int kernel_scan_for_files(struct fuzzer_state *state, int part);
void kernel_dump_file_names(struct fuzzer_state *state);
void kernel_mk_char_devices(struct fuzzer_state *state);
void dump_to_file(const char *dump_file_name, const void *data, size_t size);
void start_forksrv(void);

typedef void (*stopper_func_t)(struct fuzzer_state *state);

/**
 * @brief Creates and initialize the invoker state.
 *
 * @ingroup state_management
 */
struct fuzzer_state *create_state(int argc, const char *argv[], stopper_func_t stopper_func);

void stop_processing(struct fuzzer_state *state);

bool is_native_invoker(struct fuzzer_state *state);

int get_num_errors_returned(struct fuzzer_state *state);

bool syscalls_inhibited(struct fuzzer_state *state);
void inhibit_syscalls(struct fuzzer_state *state, bool inhibited);

static inline long lkl_exit_wrapper(long result)
{
  compiler_exit_lkl();
  return result;
}

#ifdef USE_LKL
// Appending 6 literal zero elements ensures `params` argument of lkl_syscall()
// has at least 6 dereferenceable elements.
#define LKL_SAFE_SYSCALL(name, ...) \
    (compiler_enter_lkl(), lkl_exit_wrapper( \
        lkl_syscall(__lkl__NR_##name, (long[]){__VA_ARGS__, 0, 0, 0, 0, 0, 0})))
#define LKL_ERRNO(retval) (retval)
#define LKL_STRERROR(retval) lkl_strerror((retval))
#else
void warn_lkl_not_supported(void);
#define LKL_SAFE_SYSCALL(name, ...) (warn_lkl_not_supported(), 0)
#define LKL_ERRNO(retval) (warn_lkl_not_supported(), 0)
#define LKL_STRERROR(retval) (warn_lkl_not_supported(), (const char *)NULL)
#endif

#define INVOKE_SYSCALL_0(state, syscall_name) \
    (syscalls_inhibited(state) ? 0 : (is_native_invoker(state) ? \
        syscall(SYS_##syscall_name) : \
        LKL_SAFE_SYSCALL(syscall_name, 0 /* dummy */)))
#define INVOKE_SYSCALL(state, syscall_name, ...) \
    (syscalls_inhibited(state) ? 0 : (is_native_invoker(state) ? \
        syscall(SYS_##syscall_name, __VA_ARGS__) : \
        LKL_SAFE_SYSCALL(syscall_name, __VA_ARGS__)))
#define GET_ERRNO(state, returned_value_if_lkl) \
    (is_native_invoker(state) ? \
        errno : \
        LKL_ERRNO(returned_value_if_lkl))
#define STRERROR(state, returned_value_if_lkl) \
    (is_native_invoker(state) ? \
        strerror(errno) : \
        LKL_STRERROR(returned_value_if_lkl))

#define CHECK_THAT(x) check_that_impl((x), #x)
#define CHECK_INVOKER_ERRNO(state, x) check_invoker_errno_impl((state), (x), #x)

static inline void check_that_impl(int x, const char *line)
{
  if (!x) {
    fprintf(stderr, "Check failed: %s\n", line);
    abort();
  }
}

static inline void check_invoker_errno_impl(struct fuzzer_state *state, long err, const char *line)
{
  if (err != 0) {
    fprintf(stderr, "Check failed: %s (%s)\n", line, STRERROR(state, err));
    abort();
  }
}

/// Whether `x` fits in 8 bits
#define IS_U8(x)  (((x) & ~0xffLLu      ) == 0)
/// Whether `x` fits in 16 bits
#define IS_U16(x) (((x) & ~0xffffLLu    ) == 0)
/// Whether `x` fits in 32 bits
#define IS_U32(x) (((x) & ~0xffffffffLLu) == 0)

#endif // KBDYSCH_H
