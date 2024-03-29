#ifndef KBDYSCH_INVOKER_UTILS_H
#define KBDYSCH_INVOKER_UTILS_H

#include "kbdysch/input.h"
#include "kbdysch/kbdysch.h"
#include "kbdysch/logging.h"

#include <syscall.h>
#include <setjmp.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LOG_ASSIGN(fmt, ...) \
  if (name) { \
    INVOKER_TRACE(state, ("  Assigned %s = " fmt), name, __VA_ARGS__); \
  }
#define LOG_RETURN(fmt, ...) \
  if (name) { \
    INVOKER_TRACE(state, ("  Returned %s = " fmt), name, __VA_ARGS__); \
  }

/// Whether variable is **input**, **output** or **bi-directional** syscall argument
typedef enum {
  IN,
  OUT,
  INOUT,
} direction_t;

/// \defgroup state_management Fuzzer state management
/// @{

jmp_buf *res_get_stopper_env(struct fuzzer_state *state);

/**
 * @brief Checkpoints the current input state
 *
 * @warning No recursive checkpointing supported!
 */
void res_save_state(struct fuzzer_state *state);

/**
 * @brief Restores the last checkpointed input state
 *
 * @param state         Fuzzer state
 * @param for_partition Current partition index to switch to
 */
void res_restore_state(struct fuzzer_state *state, int for_partiton);

/**
 * @brief Returns the total configured partition count
 */
int res_get_part_count(const struct fuzzer_state *state);

/// @}

/// \defgroup input_generation Generators for input argument values
///
/// @note Partitions should be processed in order, indexed from 0 to (count - 1).
/// Specifically, some input values are cached when 0-th partition is processed!
///
/// @{

static inline uint64_t res_get_named_uint(struct fuzzer_state *state,
                                          const char *name, size_t size) {
  uint64_t result = res_get_uint(state, size);
  LOG_ASSIGN("%zd / %zx", (int64_t)result, (int64_t)result);
  return result;
}

/**
 * @brief Generates an integer from range [min, max] (inclusive)
 *
 * @param state Fuzzer state
 * @param min   Minimum value
 * @param max   Maximum value
 * @return An integer in the range from `min` to `max`, inclusive
 */
int64_t res_get_integer_from_range(struct fuzzer_state *state, const char *name, int64_t min, int64_t max);

void set_fd_guard(struct fuzzer_state *state, int max_fd);

/**
 * @brief Generates a file descriptor number
 *
 * Generates an integer semantically being a file descriptor corresponding to
 * the file system currently being examined (according to `state`),
 * if in comparison mode.
 *
 * It is responsibility of this function to return "semantically equivalent"
 * FDs for every file system image, supposing there was called `res_save_state`
 * just before the argument initialization phase and `res_save_restore` just
 * before initializing the first variable of the particular filesystem.
 *
 * @note This function can return `-1`.
 */
int res_get_fd(struct fuzzer_state *state, const char *name);

/**
 * @brief Generates the **size** of the array from the range (inclusive)
 *
 * @note The **contents** of array should be recursively initialized according
 * to their types separately!
 */
size_t res_decide_array_size(struct fuzzer_state *state, const char *name, size_t min, size_t max);

/**
 * @brief Initializes the byte buffer contents (both data and size)
 *
 * @param state  Fuzzer state
 * @param buf    Pointer to data of this buffer (`MAX_BUFFER_LEN` bytes)
 * @param length Pointer to length variable for this buffer
 * @param dir    Whether this buffer represents **input** data, **output** data
 * or both **input and output**
 * @note Some initialization may be skipped according to the buffer's direction
 */
void res_fill_buffer(struct fuzzer_state *state, const char *name, buffer_t buf, uint64_t *length, direction_t dir);

/**
 * @brief Initializes the file name
 *
 * It is responsibility of this function to generate file names not getting out
 * of the file system being currently under test (accroding to `state`).
 *
 * The names generated are the same except for the mount point prefix.
 *
 * @param state Fuzzer state
 * @param value Buffer to fill with the file name (`MAX_FILE_NAME_LEN` bytes)
 */
void res_fill_file_name(struct fuzzer_state *state, const char *name, char *value);

/**
 * @brief Initialize arbitrary NUL-terminated string
 *
 * @param state Fuzzer state
 * @param value Buffer to fill with the string contents (`MAX_STRING_LEN` bytes)
 */
void res_fill_string(struct fuzzer_state *state, const char *name, char *value);

/// @}

/// \defgroup output_processing Processing of syscall output values
/// @{

void res_process_integer(struct fuzzer_state *state, const char *name, uint64_t reference, uint64_t value);
void res_process_errno(struct fuzzer_state *state, const char *name, uint64_t reference, int64_t value);

/**
 * @brief Processes the returned file descriptor numbers
 *
 * Use this function to register a file descriptor for use by res_get_fd().
 */
void res_process_fd(struct fuzzer_state *state, const char *name, int reference, int value);

void res_process_length(struct fuzzer_state *state, const char *name, uint64_t refLength, uint64_t length);
void res_process_buffer(struct fuzzer_state *state, const char *name, buffer_t refBuf, uint64_t refLength, buffer_t buf, uint64_t length, direction_t dir);

void res_process_file_name(struct fuzzer_state *state, const char *name, const char *reference, const char *value);

void res_process_string(struct fuzzer_state *state, const char *name, const char *reference, const char *value);

int res_need_recurse_into_pointees(struct fuzzer_state *state, const char *name, void *reference, void *value);

/// @}

/**
 * @brief Request patching of the FS image in its current state
 *
 * The file system if being unmounted first, then patched and mounted again.
 *
 * @note This is not compatible with the comparison mode.
 */
void kernel_perform_patching(struct fuzzer_state *state);

void kernel_perform_maintainance(struct fuzzer_state *state);

/**
 * @brief Remount all file systems
 *
 * @note It is OK to call this when in comparison mode.
 */
void kernel_perform_remount(struct fuzzer_state *state);

/**
 * @brief The single entry point of fuzzer syscall invoker
 *
 * There can be only one generated invoker per fuzzer binary.
 * There can be multiple invokers corresponding to different fuzzers
 * (such as one for file systems and one for networking)
 *
 * @param state Fuzzer state
 * @param opc   One-byte-width operation selector
 */
void invoke_next_op(struct fuzzer_state *state, uint8_t opc);

/**
 * @brief Generates integral enumeration value
 *
 * @note In its expected use, all branches in this function
 * can be decided at compile-time.
 *
 * @ingroup input_generation
 *
 * @param state       Current fuzzer state
 * @param opts_ored   All possible options, bitwise ORed
 * @param opt_values  An array of separate possible options
 * @param opt_names   An array of option names (for debug purposes)
 * @param opt_count   Length of both `opt_values` and `opt_names` arrays
 * @return  A value generated
 * @warning Return values can be not among `opt_values` if
 * this function considers them to be bitmsks.
 */
static inline uint64_t invoker_read_int_enum(struct fuzzer_state *state, const char *name, const uint64_t opts_ored, const uint64_t opt_values[], const char *opt_names[], int opt_count)
{
  /* compile-time */ const int total_set_bit_count = __builtin_popcount(opts_ored);
  /* compile-time */ const int read_raw =
      total_set_bit_count <= opt_count * 1.5 &&
      total_set_bit_count >= opt_count * 0.75 &&
      opt_count > 3;
  // technically, all the if-else-ifs here can be decided at compile-time
  uint64_t result;
  if (read_raw) {
    if (IS_U8(opts_ored))
      result = res_get_u8(state);
    else if (IS_U16(opts_ored))
      result = res_get_u16(state);
    else if (IS_U32(opts_ored))
      result = res_get_u32(state);
    else
      result = res_get_u64(state);
    LOG_ASSIGN("%zx", result);
  } else {
    int selector = res_get_u8(state) % opt_count;
    result = opt_values[selector];
    LOG_ASSIGN("%zd (%s)", result, opt_names[selector]);
  }
  return result;
}

/**
 * @brief Selects one of the string options specified
 *
 * @ingroup input_generation
 *
 * @param state      Current fuzzer state
 * @param opt_values An array of possible options
 * @param opt_count  Length of the `opt_values` array
 * @return One of the specified options
 */
static inline const char *invoker_read_string_enum(struct fuzzer_state *state, const char *name, const char *opt_values[], int opt_count)
{
  int selector = res_get_u8(state) % opt_count;
  const char *result = opt_values[selector];
  LOG_ASSIGN("%s", result);
  return result;
}

/// \defgroup harness_utils Invoker-related utility functions for harnesses
/// \@{

typedef void (*invoker_entry_t)(struct fuzzer_state *, uint8_t);

void exit_if_too_many_errors(struct fuzzer_state *state);
void skip_block_if_requested(struct fuzzer_state *state, unsigned block_index);
void align_next_block(struct fuzzer_state *state, int block_index, unsigned decoded_bytes);
size_t do_invoke(struct fuzzer_state *state, int block_index,
                 invoker_entry_t invoker_entry);
void print_summary_at_exit(struct fuzzer_state *state);
/// \@}

#ifdef __cplusplus
}
#endif

#endif // KBDYSCH_INVOKER_UTILS_H
