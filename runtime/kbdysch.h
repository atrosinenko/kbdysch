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
///
/// @note Should not be called on hot code paths.
///
/// @{

int get_bool_knob(const char *name, int default_value);
int get_int_knob(const char *name, int default_value);
const char *get_string_knob(const char *name, const char *default_value);

/// @}

void kernel_setup_disk(struct fuzzer_state *state, const char *filename, const char *fstype);
void kernel_configure_diskless(struct fuzzer_state *state, const char *mpoint);
void kernel_boot(struct fuzzer_state *state, const char *cmdline);
size_t kernel_read_from_file(struct fuzzer_state *state, const char *filename, const void *data, size_t size);
void kernel_write_to_file(struct fuzzer_state *state, const char *filename, const void *data, size_t size, int write_may_fail);
void kernel_write_string_to_file(struct fuzzer_state *state, const char *filename, const char *str, int write_may_fail);
int kernel_open_device_by_sysfs_name(struct fuzzer_state *state, const char *name, const char *sysfs_id, int dev_kind);
int kernel_scan_for_files(struct fuzzer_state *state, int part);
void kernel_dump_file_names(struct fuzzer_state *state);
void kernel_mk_char_devices(struct fuzzer_state *state);
void dump_to_file(const char *dump_file_name, const void *data, size_t size);
void start_forksrv(void);

/**
 * @brief Creates and initialize the invoker state.
 *
 * @ingroup state_management
 */
struct fuzzer_state *create_state(int argc, const char *argv[], void (*stopper)(void));

int is_native_invoker(struct fuzzer_state *state);

static inline long lkl_exit_wrapper(long result)
{
  compiler_exit_lkl();
  return result;
}

#ifdef USE_LKL
#define INVOKE_SYSCALL_0(state, syscall_name) \
    (compiler_enter_lkl(), \
    lkl_exit_wrapper((is_native_invoker(state)) ? syscall(SYS_##syscall_name) : lkl_syscall(__lkl__NR_##syscall_name, (long[]){0, 0, 0, 0, 0, 0 /* ensure >=6 dereferenceable elements */})))
#define INVOKE_SYSCALL(state, syscall_name, ...) \
    (compiler_enter_lkl(), \
    lkl_exit_wrapper((is_native_invoker(state) ? syscall(SYS_##syscall_name, __VA_ARGS__) : lkl_syscall(__lkl__NR_##syscall_name, (long[]){__VA_ARGS__, 0, 0, 0, 0, 0, 0 /* ensure >=6 dereferenceable elements */}))))
#define GET_ERRNO(state, returned_value_if_lkl) (is_native_invoker(state) ? errno : (returned_value_if_lkl))
#define STRERROR(state, returned_value_if_lkl)  (is_native_invoker(state) ? strerror(errno) : lkl_strerror(returned_value_if_lkl))
#else
void warn_lkl_not_supported(void);
#define INVOKE_SYSCALL_0(state, syscall_name) \
    (is_native_invoker(state) ? syscall(SYS_##syscall_name) : (warn_lkl_not_supported(), 0))
#define INVOKE_SYSCALL(state, syscall_name, ...) \
    (is_native_invoker(state) ? syscall(SYS_##syscall_name, __VA_ARGS__) : (warn_lkl_not_supported(), 0))
#define GET_ERRNO(state, returned_value) (is_native_invoker(state) ? errno : (warn_lkl_not_supported(), 0))
#define STRERROR(state, returned_value)  (is_native_invoker(state) ? strerror(errno) : (warn_lkl_not_supported(), (const char *)NULL))
#endif

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
