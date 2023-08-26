#ifndef KBDYSCH_KBDYSCH_H
#define KBDYSCH_KBDYSCH_H

#include "kbdysch/common-defs.h"
#include "kbdysch/compiler.h"
#include "kbdysch/logging.h"

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <syscall.h> // for SYS_* numbers

#ifdef USE_LKL
// Workaround for "redefinition of 'ipc_perm'"
#define ipc_perm __ipc_perm
// Workaround for
//   error: assigning to 'vring_desc_t *' (aka 'lkl_vring_desc *') from incompatible type 'void *'
// when including kbdysch.h from a C++ source.
#define _LKL_LINUX_VIRTIO_RING_H
#include "lkl.h"
#undef ipc_perm
#endif

#ifdef __cplusplus
extern "C" {
#endif

void res_add_to_known_strings(struct fuzzer_state *state, const char *string);

unsigned kernel_setup_disk(struct fuzzer_state *state, const char *filename, const char *fstype);
unsigned kernel_setup_raw_disk(struct fuzzer_state *state, const char *fstype, size_t size);
void kernel_configure_diskless(struct fuzzer_state *state, const char *mpoint);
void kernel_boot(struct fuzzer_state *state, const char *cmdline);
void kernel_invoke_write_to_file(struct fuzzer_state *state);
int kernel_open_device_by_sysfs_name(struct fuzzer_state *state, const char *name, const char *sysfs_id, int dev_kind);
int kernel_scan_for_files(struct fuzzer_state *state, int part);
void kernel_dump_file_names(struct fuzzer_state *state);
void kernel_mk_char_devices(struct fuzzer_state *state);
void dump_to_file(const char *dump_file_name, const void *data, size_t size);
void start_forksrv(void);
void spawn_thread(struct fuzzer_state *state, void *(*thread_fn)(void *),
                  void *arg);
void *map_host_huge_pages_if_possible(struct fuzzer_state *state, const char *desc, int fd, size_t size);
void *alloc_target_pages(struct fuzzer_state *state, size_t size, int prot);

typedef void (*stopper_func_t)(struct fuzzer_state *state);

/**
 * @brief Creates and initialize the invoker state.
 *
 * @ingroup state_management
 */
struct fuzzer_state *create_state(int argc, const char *argv[], stopper_func_t stopper_func);

void stop_processing(struct fuzzer_state *state);

bool is_native_invoker(const struct fuzzer_state *state);

int get_num_errors_returned(const struct fuzzer_state *state);

bool syscalls_inhibited(const struct fuzzer_state *state);
void inhibit_syscalls(struct fuzzer_state *state, bool inhibited);

static inline long lkl_exit_wrapper(long result)
{
  compiler_exit_lkl();
  return result;
}

#ifdef USE_LKL
// Appending 6 literal zero elements ensures `params` argument of lkl_syscall()
// has at least 6 dereferenceable elements.
#ifdef USE_DUMMY_LKL
#define LKL_SC_NR(name) __NR_##name
#else
#define LKL_SC_NR(name) __lkl__NR_##name
#endif

#ifdef __cplusplus
// Workaround for g++:
//   error: taking address of temporary array
static inline
long lkl_syscall_overloaded(long num, long a = 0, long b = 0, long c = 0,
                            long d = 0, long e = 0, long f = 0) {
  long args[] = {a, b, c, d, e, f};
  return lkl_syscall(num, args);
}
#define LKL_SAFE_SYSCALL(name, ...) \
    (compiler_enter_lkl(), lkl_exit_wrapper( \
        lkl_syscall_overloaded(LKL_SC_NR(name), __VA_ARGS__)))
#else
#define LKL_SAFE_SYSCALL(name, ...) \
    (compiler_enter_lkl(), lkl_exit_wrapper( \
        lkl_syscall(LKL_SC_NR(name), (long[]){__VA_ARGS__, 0, 0, 0, 0, 0, 0})))
#endif // __cplusplus

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

#define STRERROR_OR_POSITIVE(state, returned_value) \
    ((returned_value) < 0 ? STRERROR(state, returned_value) : "No error")

#define CHECK_THAT(x) check_that_impl((x), __FILE__, __LINE__, #x)
#define CHECK_INVOKER_ERRNO(state, x) check_invoker_errno_impl((state), (x), #x)

static inline void check_that_impl(int x, const char *file_name, int line, const char *expr)
{
  if (!x) {
    LOG_FATAL("%s:%d: Check failed: %s", file_name, line, expr);
    abort();
  }
}

static inline void check_invoker_errno_impl(struct fuzzer_state *state, long err, const char *line)
{
  if (err != 0) {
    LOG_FATAL("Check failed: %s (%s)", line, STRERROR(state, err));
    abort();
  }
}

#define CHECKED_SYSCALL_0(state, syscall_name) \
    checked_syscall_impl(state, INVOKE_SYSCALL_0(state, syscall_name), \
                         __FILE__, __LINE__, #syscall_name)

#define CHECKED_SYSCALL(state, syscall_name, ...) \
    checked_syscall_impl(state, INVOKE_SYSCALL(state, syscall_name, __VA_ARGS__), \
                         __FILE__, __LINE__, #syscall_name)

static inline long checked_syscall_impl(
    struct fuzzer_state *state, long ret,
    const char *file_name, int line, const char *syscall_name) {
  if (ret < 0) {
    long err = GET_ERRNO(state, ret);
    const char *msg = STRERROR(state, ret);
    LOG_FATAL("%s:%d: System call %s() failed: error %d (%s)",
              file_name, line, syscall_name, err, msg);
    abort();
  }
  return ret;
}

/// Whether `x` fits in 8 bits
#define IS_U8(x)  (((x) & ~0xffLLu      ) == 0)
/// Whether `x` fits in 16 bits
#define IS_U16(x) (((x) & ~0xffffLLu    ) == 0)
/// Whether `x` fits in 32 bits
#define IS_U32(x) (((x) & ~0xffffffffLLu) == 0)

#ifdef __cplusplus
}
#endif

#endif // KBDYSCH_KBDYSCH_H
