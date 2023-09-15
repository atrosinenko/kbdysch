#include "kbdysch/kbdysch.h"

#include "kbdysch/hashing.h"
#include "kbdysch/internal-defs.h"
#include "kbdysch/invoker-utils.h"
#include "kbdysch/mutator-interface.h"
#include "kbdysch/options.h"

#include <stdint.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <syscall.h>

DECLARE_BOOL_KNOB(ignore_invalid_errno, "IGNORE_INVALID_ERRNO")

static uint8_t reference_watermark[WATERMARK_SIZE];

CONSTRUCTOR(constr)
{
  // FF 01 FD 03 ...
  for (int i = 0; i < WATERMARK_SIZE; ++i) {
    reference_watermark[i] = (i % 2) ? i : (255 - i);
  }
}

DECLARE_BOOL_KNOB(no_new_files, "NO_NEW_FILES")
DECLARE_BOOL_KNOB(simple_file_names, "SIMPLE_NAMES")
DECLARE_BOOL_KNOB(fault_is_ok, "FAULT_IS_OK")
DECLARE_INT_KNOB(opt_max_file_name_length, "MAX_FILE_NAME_LENGTH");

DEBUG_COUNTER(file_names_reused, "File names reused")
DEBUG_COUNTER(file_names_created, "File names created")
DEBUG_COUNTER(valid_fds, "Valid FDs")
DEBUG_COUNTER(invalid_fds, "Invalid FDs")
DEBUG_COUNTER(unique_fds, "Unique FDs")

jmp_buf *res_get_stopper_env(struct fuzzer_state *state)
{
  return &state->stopper;
}

void res_save_state(struct fuzzer_state *state)
{
  memcpy(&state->saved_state, &state->current_state, sizeof(saveable_state_t));
}

void res_restore_state(struct fuzzer_state *state, int for_partiton)
{
  memcpy(&state->current_state, &state->saved_state, sizeof(saveable_state_t));
  state->mutable_state.current_part = for_partiton;
}

static uint64_t res_rand(struct fuzzer_state *state)
{
  state->current_state.rng_state *= 17239000000001LLu; // TODO use better multiplier
  return state->current_state.rng_state >> 1; // so, may be even
}

int res_get_part_count(const struct fuzzer_state *state)
{
  return state->constant_state.part_count;
}

void res_align_next_to(struct fuzzer_state *state, size_t alignment)
{
  state->current_state.offset = (state->current_state.offset + alignment - 1) / alignment * alignment;
}

void res_skip_bytes(struct fuzzer_state *state, size_t bytes_to_skip)
{
  state->current_state.offset += bytes_to_skip;
}

static uint8_t *get_and_consume(struct fuzzer_state *state, size_t bytes)
{
  uint8_t *result = state->constant_state.input_buffer + state->current_state.offset;
  state->current_state.offset += bytes;
  return result;
}

uint64_t res_get_uint(struct fuzzer_state *state, const char *name, size_t size)
{
  uint64_t result = 0;
  assert(size == 1 || size == 2 || size == 4 || size == 8);
  res_align_next_to(state, size);
  if (state->current_state.offset + size > state->constant_state.length)
    stop_processing(state);

  memcpy(&result, get_and_consume(state, size), size);
  if (name != NULL) {
    LOG_ASSIGN("%zd / %zx", (int64_t)result, (int64_t)result);
  }
  return result;
}

void res_copy_bytes(struct fuzzer_state *state, void *ptr, size_t size)
{
  if (state->current_state.offset + size > state->constant_state.length)
    stop_processing(state);

  uint8_t *source_ptr = get_and_consume(state, size);
  memcpy(ptr, source_ptr, size);
}

int64_t res_get_integer_from_range(struct fuzzer_state *state, const char *name, int64_t min, int64_t max)
{
  assert(min < max);
  uint64_t range = max - min + 1;
  int64_t result;

  if (IS_U8(range))
    result = min + res_get_u8(state) % range;
  else if (IS_U16(range))
    result = min + res_get_u16(state) % range;
  else if (IS_U32(range))
    result = min + res_get_u32(state) % range;
  else
    result = min + res_get_u64(state) % range;

  LOG_ASSIGN("%zd / %zx", result, result);
  return result;
}

size_t res_decide_array_size(struct fuzzer_state *state, const char *name, size_t min, size_t max)
{
  assert((int64_t)min >= 0 && (int64_t)max >= 0);
  size_t result = (size_t)res_get_integer_from_range(state, NULL, (int64_t)min, (int64_t)max);

  LOG_ASSIGN("%zd", result);
  return result;
}

void res_add_to_known_strings(struct fuzzer_state *state, const char *string)
{
  size_t length = strlen(string);
  fast_hash_t hash = kbdysch_compute_fast_hash(string, length);

  for (int i = 0; i < state->mutable_state.string_count; ++i) {
    if (state->mutable_state.string_hash[i] == hash) {
      return;
    }
  }

  int index = state->mutable_state.string_count++;
  state->mutable_state.strings[index] = strdup(string);
  state->mutable_state.string_hash[index] = hash;
  state->mutable_state.string_length[index] = length;
}

#ifdef USE_COMPACT_ENCODING
static size_t res_fill_buffer_compact(struct fuzzer_state *state, const char *name, uint8_t *buffer, size_t size) {
  uint64_t control = res_get_u64(state);
  unsigned length = control & 0xff;
  unsigned offset = (control >> 8) & 0xff;
  uint64_t six_bytes = control >> 16;

  if (length >= size)
    length = size;
  if (offset >= length)
    offset = length;
  unsigned payload_length = length - offset;
  if (payload_length > 8)
    payload_length = 8;

  for (unsigned i = 0; i < length; ++i)
    buffer[i] = '0' + (i % 10);
  memcpy(buffer + offset, &six_bytes, payload_length);
  LOG_ASSIGN("<compact initializer: %u + %u + %u>", offset, payload_length, length - offset - payload_length);
  return length;
}

void res_fill_string(struct fuzzer_state *state, const char *name, char *value) {
  size_t length = res_fill_buffer_compact(state, name, (uint8_t *)value, MAX_STRING_LEN - 1);
  value[length] = 0;
}
void res_fill_buffer(struct fuzzer_state *state, const char *name, buffer_t buf, uint64_t *length, direction_t dir) {
  *length = res_fill_buffer_compact(state, name, buf, MAX_BUFFER_LEN);
  memcpy(buf + *length, reference_watermark, WATERMARK_SIZE);
}
#else
void res_fill_string(struct fuzzer_state *state, const char *name, char *value)
{
  int16_t length = (int16_t) res_get_u16(state);
  if (length < 0) {
    // known string prefix
    int known_index = -length % state->mutable_state.string_count;
    int immediate_length = res_get_u8(state) % 32;
    strcpy(value, state->mutable_state.strings[known_index]);
    int known_length = state->mutable_state.string_length[known_index];
    if (known_length > MAX_STRING_LEN - immediate_length - 1)
      known_length = MAX_STRING_LEN - immediate_length - 1;
    char *immediate_string = value + known_length;
    res_copy_bytes(state, immediate_string, immediate_length);
    immediate_string[immediate_length] = '\0';
    res_add_to_known_strings(state, value);
    LOG_ASSIGN("\"%s\" (known prefix)", value);
  } else if (length <= 30) {
    // read string as-is if consuming <= 32 bytes in total
    res_copy_bytes(state, value, length);
    value[length] = '\0';
    LOG_ASSIGN("\"%s\" (verbatim)", value);
  } else {
    length %= 512;
    length %= (MAX_STRING_LEN - 1);
    for (int i = 0; i < length; ++i) {
      value[i] = 'a' + (i % 26);
    }
    value[length] = '\0';
    LOG_ASSIGN("<pattern string of length %d>", length);
  }
}

void res_fill_buffer(struct fuzzer_state *state, const char *name, buffer_t buf, uint64_t *length, direction_t dir)
{
  int32_t len = res_get_u32(state);
  if (dir == OUT) {
    len &= 511; // makes len >= 0
    // fastpath
    if (state->constant_state.part_count > 1) {
      // make buffer contents initially identical in case not fully overwritten
      memset(buf, 0, len);
    }
    *length = len;
    memcpy(buf + len, reference_watermark, WATERMARK_SIZE);
    return;
  }

  assert((uintptr_t)buf % 4 == 0);
  if (len < 0) {
    _Static_assert(MAX_STRING_LEN <= MAX_BUFFER_LEN, "MAX_STRING_LEN <= MAX_BUFFER_LEN");
    res_fill_string(state, name, buf);
    len = strlen(buf) + 1;
  } else if (len <= 28) {
    // read data as-is if consuming <= 32 bytes in total
    res_copy_bytes(state, buf, len);
    LOG_ASSIGN("<buffer of size %d, verbatim contents>", len);
  } else {
    len %= 512;
    len %= MAX_BUFFER_LEN;
    // fill with pseudo-random contents
    for (uint i = 0; i < compiler_length_value(len); i += 4) {
      uint64_t rnd = res_rand(state); // use 4 least significant bytes
      *(uint32_t *)(buf + i) = rnd & 0xffffffff;
    }
    LOG_ASSIGN("<buffer of size %d, pseudo-random contents>", len);
  }
  *length = len;
  // it is faster to allow overfill and put watermark afterwards
  memcpy(buf + len, reference_watermark, WATERMARK_SIZE);
}
#endif

static int res_create_file_name(struct fuzzer_state *state)
{
  static char __attribute__((aligned(4))) tmp_buf[MAX_FILE_NAME_LEN + 128];
  uint64_t chain_to = res_get_u16(state) % state->current_state.file_name_count;
  uint16_t component_length;

  TRACE(NULL, "chain_to = %d / %d / %s", chain_to, state->current_state.file_name_count, state->mutable_state.file_names[chain_to]);
  if (chain_to)
    res_mark_consumed_reference(state, RESOURCE_KIND_FILE_NAME, chain_to, 2);

  if (no_new_files) {
    DEBUG_INC(file_names_reused);
    return (int)chain_to;
  }

#ifdef USE_COMPACT_ENCODING
  component_length = res_fill_buffer_compact(state, "", (uint8_t *)tmp_buf, MAX_FILE_NAME_LEN);
  if (opt_max_file_name_length && component_length > opt_max_file_name_length)
    tmp_buf[opt_max_file_name_length] = '\0';
  if (component_length == 0) {
    DEBUG_INC(file_names_reused);
    return (int)chain_to;
  }
#else
  component_length = res_get_u16(state);
  if (component_length & 0x8000)
    return (int)chain_to; // reuse existing file name
  component_length %= 512;
  // create new path component
  if (component_length < 28) {
    // read string as-is if consuming <= 32 bytes in total
    res_copy_bytes(state, tmp_buf, component_length);
    for (int i = 0; i < component_length; ++i) {
      if (tmp_buf[i] == '.') {
        // prevent path from escaping its partition
        // TODO relax this restriction, allowing to go up the directory tree not too high
        tmp_buf[i] = '_';
      }
    }
  } else {
    // fill with pseudo-random contents
    component_length %= MAX_FILE_NAME_LEN;
    if (simple_file_names) {
      for (uint i = 0; i < compiler_length_value(component_length); ++i) {
        tmp_buf[i] = '0' + (i % 10);
      }
    } else {
      for (uint i = 0; i < compiler_length_value(component_length) + 4; i += 4) {
        uint64_t rnd = res_rand(state); // use 4 least significant bytes
        *(uint32_t *)(tmp_buf + i) = rnd & 0xffffffff;
      }
    }
  }
#endif
  tmp_buf[component_length] = '\0';

  // attach the newly created component to the selected existing one
  char *new_name =  malloc(MAX_FILE_NAME_LEN);
  int new_index = state->current_state.file_name_count++;
  // TODO Do not discard `const` qualifier somehow?
  free((void *) state->mutable_state.file_names[new_index]);
  snprintf(new_name, MAX_FILE_NAME_LEN, "%s/%s", state->mutable_state.file_names[chain_to], tmp_buf);
  state->mutable_state.file_names[new_index] = new_name;
  state->mutable_state.file_basenames[new_index] = strrchr(new_name, '/');
  mutator_open_resource(RESOURCE_KIND_FILE_NAME, new_index);
  DEBUG_INC(file_names_created);
  return new_index;
}

void res_fill_file_name(struct fuzzer_state *state, const char *name, char *value)
{
  int index_for_result = res_create_file_name(state);
  snprintf(value, MAX_FILE_NAME_LEN, "%s/%s",
      state->partitions[state->mutable_state.current_part].mount_point,
      state->mutable_state.file_names[index_for_result]
  );
  LOG_ASSIGN("%s (index %d)", value, index_for_result);
}

void set_fd_guard(struct fuzzer_state *state, int max_fd)
{
  state->current_state.guarded_fds = max_fd;
}

int res_get_fd(struct fuzzer_state *state, const char *name)
{
  int cur_part = state->mutable_state.current_part;
  uint16_t ind = res_get_u16(state) % state->partitions[cur_part].registered_fds_count;
  int result = state->partitions[cur_part].registered_fds[ind];
  if (result <= state->current_state.guarded_fds)
    result = -1;
  LOG_ASSIGN("<FD: %d>", result);
  if (result != -1)
    res_mark_consumed_reference(state, RESOURCE_KIND_FD, ind, 2);
  return result;
}

static void crash_on_difference_int(struct fuzzer_state *state, const char *descr, const char *name, uint64_t ref, uint64_t val)
{
  if (ref != val) {
    int part = state->mutable_state.current_part;
    LOG_FATAL("%s:", descr);
    LOG_FATAL("  Name = %s", name);
    LOG_FATAL("  [%s] \t %zu", state->partitions[0].fstype, ref);
    LOG_FATAL("  [%s] \t %zu", state->partitions[part].fstype, val);
    abort();
  }
}

void res_process_integer(struct fuzzer_state *state, const char *name, uint64_t reference, uint64_t value)
{
  LOG_RETURN("%zd / %zx", value, value);
  crash_on_difference_int(state, "Return values differ", name, reference, value);
}

void res_process_errno(struct fuzzer_state *state, const char *name, uint64_t reference, int64_t value)
{
  if (value == -EFAULT && !fault_is_ok) {
    LOG_FATAL("EFAULT is returned as %s. Possible reasons:", name);
    LOG_FATAL("  * some buffers should be specifically aligned (at page boundary, for example)");
    LOG_FATAL("  * some buffers should be allocated using \"guest\" mmap()");
    LOG_FATAL("Try adjusting invoker description or specify FAULT_IS_OK knob.");
    abort();
  }
  if (value < 0)
    state->current_state.num_errors_returned += 1;
  if (!ignore_invalid_errno && value < 0 && !is_native_invoker(state) &&
      STRERROR(state, (int)value) == STRERROR(state, 100500)) {
    LOG_FATAL("Invalid errno:");
    LOG_FATAL("  Name = %s", name);
    LOG_FATAL("  [%s] \t %d", state->partitions[state->mutable_state.current_part].fstype, errno);
    abort();
  }
  LOG_RETURN("%s", STRERROR(state, (int)value));
  crash_on_difference_int(state, "Errno differ", name, reference, value);
}

void res_process_fd(struct fuzzer_state *state, const char *name, int reference, int value)
{
  int part = state->mutable_state.current_part;
  if ((reference < 0) != (value < 0)) {
    LOG_FATAL("Returned FDs are inconsistent:");
    LOG_FATAL("  Name = %s", name);
    LOG_FATAL("  [%s] \t %d", state->partitions[0].fstype, reference);
    LOG_FATAL(", [%s] \t %d", state->partitions[part].fstype, value);
    abort();
  }
  if (value >= 0) {
    DEBUG_INC(valid_fds);
    LOG_RETURN("<FD: %d>", value);
  } else {
    DEBUG_INC(invalid_fds);
    LOG_RETURN("<ERR: %s>", STRERROR(state, value));
    return;
  }
  if (state->constant_state.part_count == 1) {
    // TODO Is it safe in comparison mode?
    for (int i = 0; i < state->partitions[part].registered_fds_count; ++i) {
      if (state->partitions[part].registered_fds[i] == value)
        return;
    }
  }
  // Consuming FD here may clash with manually opened FD (say, for device file).
  if (!state->mutable_state.syscalls_inhibited) {
    DEBUG_INC(unique_fds);
    int index = state->partitions[part].registered_fds_count++;
    mutator_open_resource(RESOURCE_KIND_FD, index);
    state->partitions[part].registered_fds[index] = value;
  }
}

void res_process_length(struct fuzzer_state *state, const char *name, uint64_t refLength, uint64_t length)
{
  LOG_RETURN("<length = %zu>", length);
  crash_on_difference_int(state, "Returned length differ", name, refLength, length);
}

void res_process_buffer(struct fuzzer_state *state, const char *name, buffer_t refBuf, uint64_t refLength, buffer_t buf, uint64_t length, direction_t dir)
{
  assert(refLength == length);
  if (memcmp(buf + length, reference_watermark, WATERMARK_SIZE) != 0) {
    LOG_FATAL("Corrupted buffer watermark:");
    LOG_FATAL("  Name = %s", name);
    LOG_FATAL("  Buffer size = %zu", length);
    LOG_FATAL("  Reference: %02x %02x %02x %02x...",
              reference_watermark[0], reference_watermark[1], reference_watermark[2], reference_watermark[3]);
    LOG_FATAL("  Actual:    %02x %02x %02x %02x...",
              buf[length], buf[length + 1], buf[length + 2], buf[length + 3]);
    abort();
  }
  if (refBuf != buf && memcmp(refBuf, buf, length) != 0) {
    // slow path...
    uint64_t ind;
    for (ind = 0; ind < length; ++ind) {
      if (refBuf[ind] != buf[ind])
        break;
    }
    int part = state->mutable_state.current_part;
    LOG_FATAL("Returned buffers differ:");
    LOG_FATAL("  Name = %s", name);
    LOG_FATAL("  Position = %zu", ind);
    LOG_FATAL("  [%s] \t %02x", state->partitions[0].fstype, refBuf[ind] & 0xff);
    LOG_FATAL("  [%s] \t %02x", state->partitions[part].fstype, buf[ind] & 0xff);
    abort();
  }
}

void res_process_file_name(struct fuzzer_state *state, const char *name, const char *reference, const char *value)
{
  // TODO
}

void res_process_string(struct fuzzer_state *state, const char *name, const char *reference, const char *value)
{
  if (reference != value && strncmp(reference, value, MAX_STRING_LEN) != 0) {
    int part = state->mutable_state.current_part;
    LOG_FATAL("Returned strings differ:");
    LOG_FATAL("  Name = %s", name);
    LOG_FATAL("  [%s] \t %s", state->partitions[0].fstype, reference);
    LOG_FATAL("  [%s] \t %s", state->partitions[part].fstype, value);
    abort();
  }
  LOG_RETURN("%s", value);
}

int res_need_recurse_into_pointees(struct fuzzer_state *state, const char *name, void *reference, void *value)
{
  // recursing even if reference == value,
  // since there can be generic validation apart from comparison
  if ((reference == NULL) != (value == NULL)) {
    int part = state->mutable_state.current_part;
    LOG_FATAL("Returned pointers are inconsistent:");
    LOG_FATAL("  Name = %s", name);
    LOG_FATAL("  [%s] \t %p", state->partitions[0].fstype, reference);
    LOG_FATAL("  [%s] \t %p", state->partitions[part].fstype, value);
    abort();
  }
  return value != NULL;
}

void res_close_all_fds(struct fuzzer_state *state)
{
  for (int part = 0; part < state->constant_state.part_count; ++part) {
    for (int i = 0; i < state->partitions[part].registered_fds_count; ++i) {
      INVOKE_SYSCALL(state, close, state->partitions[part].registered_fds[i]);
    }
    state->partitions[part].registered_fds[0] = -1;
    state->partitions[part].registered_fds_count = 1;
  }
}
