#ifndef INTERNAL_DEFS_H
#define INTERNAL_DEFS_H

#include "kbdysch.h"

#include <setjmp.h>

#ifdef USE_LKL
#include "lkl.h"
#include "lkl_host.h"
#include <sys/mount.h>
#else
struct lkl_disk {
  int dummy;
};
#endif

/**
 * Presense of one of the following words (case insensitive) in the `printk` message
 * is considered as failure (can be disabled).
 */
static const char *BAD_WORDS[] = {
  "error",
  "corrupt",
  "oops",
  "undefined behavior",
  "call trace"
};

#define MAX_FILE_NAME_COUNT (1 << 16)
#define MAX_REGISTERED_FDS 1024
#define MAX_STRING_COUNT (1 << 16)

#define MOUNT_POINT_LEN 128
#define FSTYPE_LEN 32
#define ACCESS_HISTORY_LEN 1024

typedef struct {
  char mount_point[MOUNT_POINT_LEN]; ///< Mount points of configured partitions
  char fstype[FSTYPE_LEN];           ///< Type of the file system, as recognized by mount
  struct lkl_disk disk; ///< LKL structure associated with this partition
  int disk_id;          ///< LKL disk ID associated with this partition

  int registered_fds[MAX_REGISTERED_FDS]; ///< File descriptors referencing this partition
  int registered_fds_count;               ///< Count of actual entries in `registered_fds`

  int off_start[ACCESS_HISTORY_LEN]; ///< Start offset of the recorded access
  int off_end  [ACCESS_HISTORY_LEN]; ///< End offset of the recorded access
  long long access_count; ///< Total number of accesses issued on this partition
  int off_cur; ///< Index of current offset to be recorded (in a circular buffer manner)

  char *data;  ///< Pointer to partition image data
  size_t size; ///< Size of partition image data in bytes
} partition_t;

/**
 * @brief Fuzzer state that does not change, once initialized
 */
typedef struct {
  uint8_t input_buffer[MAX_INPUT_LEN]; ///< Bytes representing the testcase
  ssize_t length;   ///< Total length of the testcase
  int part_count;   ///< Total count of partitions configured
  bool diskless;    ///< Configured without any partitions
  bool native_mode; ///< Flag: whether we are issuing syscalls to native kernel instead of LKL
  bool log_assigns;
} constant_state_t;

/**
 * @brief These values **does change** during execution but **are not saved** by
 * save/restore machinery
 */
typedef struct {
  const char *file_names[MAX_FILE_NAME_COUNT]; ///< File names relative to the FS root

  const char *strings[MAX_STRING_COUNT]; ///< Known strings
  uint32_t string_hash[MAX_STRING_COUNT]; ///< Some non-cryptographic hashes of these strings
  uint32_t string_length[MAX_STRING_COUNT]; ///< Lengths of these strings
  int string_count; ///< Count of known strings
  int current_part;   ///< Current partition index to issue syscalls against (0-indexed)
  bool patch_was_invoked; ///< PATCH operation was already invoked during this run
  bool syscalls_inhibited; ///< Temporarily make INVOKE_SYSCALL no-op
} mutable_state_t;

/**
 * @brief Fuzzer state that **does change** during execution and should be
 * saved by `res_save_state` and restored by `res_restore_state`.
 *
 * @warning Should be `memcpy`-copyable!
 */
typedef struct {
  int file_name_count; ///< Count of file names initialized so far
  int guarded_fds;
  int num_errors_returned;
  uint64_t offset;    ///< Current offset inside the testcase
  uint64_t rng_state; ///< Current state of RNG
} saveable_state_t;

/**
 * @brief Fuzzer state
 */
struct fuzzer_state {
  stopper_func_t stopper_func;
  jmp_buf stopper;
  constant_state_t constant_state;
  partition_t partitions[MAX_PART_COUNT];
  mutable_state_t mutable_state;
  saveable_state_t current_state;
  saveable_state_t saved_state;
};

void res_close_all_fds(struct fuzzer_state *state);

#endif // INTERNAL_DEFS_H
