#ifndef INVOKER_UTILS_H
#define INVOKER_UTILS_H

#include "kbdysch.h"

#include <syscall.h>
#include <setjmp.h>

/**
 * @brief Whether invoker should log assigned and returned values to stderr
 */
int res_should_log_assignments(struct fuzzer_state *state);

#define LOG_ASSIGN(fmt, ...) \
  if (res_should_log_assignments(state) && name) { \
    fprintf(stderr, "  Assigned %s = " fmt "\n", name, __VA_ARGS__); \
  }
#define LOG_RETURN(fmt, ...) \
  if (res_should_log_assignments(state) && name) { \
    fprintf(stderr, "  Returned %s = " fmt "\n", name, __VA_ARGS__); \
  }


/// Whether variable is **input**, **output** or **bi-directional** syscall argument
typedef enum {
  IN,
  OUT,
  INOUT,
} direction_t;

/// \defgroup state_management Fuzzer state management
/// @{

/**
 * @brief Loads fuzzer testcase from the standard input
 */
void res_load_whole_stdin(struct fuzzer_state *state);

/**
 * @brief Sets the previously loaded fuzzer input
 */
void res_set_input_data(struct fuzzer_state *state, uint8_t *data, size_t size);

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
int res_get_part_count(struct fuzzer_state *state);

/**
 * @brief Whether this fuzzer if configured to invoke syscalls on host kernel or not
 */
int res_is_native_invoker(struct fuzzer_state *state);

/**
 * @brief Returns current offset in the fuzzer input data (for debug purposes)
 */
size_t res_get_cur_offset(const struct fuzzer_state *state);

/**
 * @brief Returns the total fuzzer input length (for debug purposes)
 */
ssize_t res_get_input_length(const struct fuzzer_state *state);

/**
 * @brief Explicitly skips enough number of input bytes, so the next position
 * will be aligned as requested
 *
 * @note Some bytes may be skipped implicitly for the alignment purposes as well
 */
void res_align_next_to(struct fuzzer_state *state, size_t alignment);

/**
 * @brief Explicitly skip the specified amount of input bytes
 */
void res_skip_bytes(struct fuzzer_state *state, size_t bytes_to_skip);

/// @}

/// \defgroup input_generation Generators for input argument values
///
/// @note Partitions should be processed in order, indexed from 0 to (count - 1).
/// Specifically, some input values are cached when 0-th partition is processed!
///
/// @{

/**
 * @brief Reads 1, 2, 4 or 8-bytes size integer from the fuzzer input
 */
uint64_t res_get_uint(struct fuzzer_state *state, const char *name, size_t size);

/**
 * @brief Copy raw bytes from the input
 *
 * @param state Fuzzer state
 * @param ptr   Pointer to buffer to be filled in
 * @param size  Count of bytes to copy
 */
void res_copy_bytes(struct fuzzer_state *state, void *ptr, size_t size);

/**
 * @brief Generates an integer from range [min, max] (inclusive)
 *
 * @param state Fuzzer state
 * @param min   Minimum value
 * @param max   Maximum value
 * @return An integer in the range from `min` to `max`, inclusive
 */
int64_t res_get_integer_from_range(struct fuzzer_state *state, const char *name, int64_t min, int64_t max);

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


static inline uint8_t res_get_u8(struct fuzzer_state *state)
{
  return (uint8_t)res_get_uint(state, NULL, 1);
}

static inline uint16_t res_get_u16(struct fuzzer_state *state)
{
  return (uint16_t)res_get_uint(state, NULL, 1);
}

static inline uint32_t res_get_u32(struct fuzzer_state *state)
{
  return (uint32_t)res_get_uint(state, NULL, 1);
}

static inline uint64_t res_get_u64(struct fuzzer_state *state)
{
  return (uint64_t)res_get_uint(state, NULL, 1);
}

/// @}

/// \defgroup output_processing Processing of syscall output values
/// @{

void res_process_integer(struct fuzzer_state *state, const char *name, uint64_t reference, uint64_t value);
void res_process_errno(struct fuzzer_state *state, const char *name, uint64_t reference, uint64_t value);

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

#endif // INVOKER_UTILS_H
