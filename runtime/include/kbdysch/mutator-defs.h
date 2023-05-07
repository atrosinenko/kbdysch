#ifndef KBDYSCH_MUTATOR_DEFS_H
#define KBDYSCH_MUTATOR_DEFS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Common definitions for harness executables and mutator library

#define MUTATOR_SHM_VARS_ENV_NAME "__KBDYSCH_MUTATOR_SHM_VARS_ID"
#define MUTATOR_SHM_LOG_ENV_NAME "__KBDYSCH_MUTATOR_SHM_LOG_ID"

// Mutator and harness communicate by means of dedicated SHM areas.
// Assumptions:
// * Mutator should never crash, even on malformed SHM contents.
//   After all, if fuzzer finds a crash, it is quite expectably that
//   harness-writable memory can be corrupted.
// * Mutator library and harness executable should match exactly,
//   no forward/backward compatibility is assumed for now.
// * Each successful invocation of the same harness should produce the
//   same layout of variables SHM area. It is perfectly OK for different
//   harnesses or differently-configured harness to produce different layouts
//   * this area can be parsed once during fuzzing session warm-up and then
//     pointers can be remembered
//
// Variables area layout:
//
// N records are concatenated without any padding in between.
// N does not change across fuzzing session.
// Each record has the following layout:
// - struct mutator_var_header
// - (name_bytes) bytes with variable name (not necessary 0-terminated)
// - (bytes_per_element * max_num_elements) bytes of payload
// The last record should have type == MUTATOR_VAR_STOP.
//
// Then, at MUTATOR_SHM_VARS_BYTES offset, another area is located that
// is zeroed by the forkserver before each run. This temporary area has
// the same layout as the first one, but only a few supported fields are
// updated.
//
// Log area layout:
//
// HASH_CHARS bytes of input hash is followed by log records.
// Each harness run can produce an arbitrary number of log records
// concatenated without any padding in between.
// Each record has the following layout:
// - struct mutator_log_record_header
// - payload depending on the type field
// The last record should have type == MUTATOR_LOG_STOP.

enum mutator_fixed_record_type {
  MUTATOR_VAR_STOP = 0,
  MUTATOR_VAR_COUNTERS,
  MUTATOR_VAR_STRINGS,
};

enum mutator_opcode {
  MUTATOR_LOG_STOP = 0,
  MUTATOR_LOG_SET_OFFSET,
  MUTATOR_LOG_NEW_RES,
  MUTATOR_LOG_REF_RES,
  MUTATOR_LOG_PROPOSE_CHANGE,
};

enum mutator_resource_kind {
  RESOURCE_KIND_FD,
  RESOURCE_KIND_FILE_NAME,
  RESOURCE_KIND_HARNESS_SPECIFIC_1,

  MUTATOR_MAX_RESOURCE_KINDS
};

#define UNALIGNED __attribute__((aligned(1)))
typedef uint16_t mutator_num_elements_t UNALIGNED;
typedef uint64_t mutator_u64_var_t UNALIGNED;

#pragma pack(push,1)
struct mutator_var_header {
  uint16_t type;
  uint16_t name_bytes;
  uint16_t bytes_per_element;
  mutator_num_elements_t max_num_elements;

  mutator_num_elements_t num_elements_real;
};

struct mutator_log_record_header {
  uint16_t type;
  uint16_t size; // including this header
};
struct mutator_log_set_offset {
  uint32_t offset;
};
struct mutator_log_new_resource {
  uint8_t kind;
  uint8_t id;
#define MUTATOR_MAX_RESOURCE_IDS 256
};
struct mutator_log_ref_resource {
  uint8_t kind;
  uint8_t id_bytes;
  uint8_t id;
  uint32_t offset;
};
struct mutator_log_propose_change {
  uint32_t offset;
  uint32_t size; // from 1 to 8 bytes
  uint64_t replacement;
};
#pragma pack(pop)

#define MUTATOR_MAX_TEST_CASE_LENGTH (1 << 20)

#define MUTATOR_MAX_VARIABLES 100
#define MUTATOR_SHM_VARS_BYTES 4000
#define MUTATOR_SHM_VAR_IN_CURRENT_AREA(ptr) \
    ((void *)(((uint8_t *)(ptr)) + MUTATOR_SHM_VARS_BYTES))

#define MUTATOR_MAX_LOG_BYTES 4000
#define MUTATOR_SHM_LOG_BYTES (HASH_CHARS + MUTATOR_MAX_LOG_BYTES)
#define MUTATOR_MAX_LOG_ENTRIES(type) (MUTATOR_MAX_LOG_BYTES / (sizeof(struct mutator_log_record_header) + sizeof(struct type)))
#define MUTATOR_MAX_OFFSETS MUTATOR_MAX_LOG_ENTRIES(mutator_log_set_offset)

#ifdef __cplusplus
}
#endif

#endif  // KBDYSCH_MUTATOR_DEFS_H
