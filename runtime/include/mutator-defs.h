#ifndef KBDYSCH_MUTATOR_DEFS_H
#define KBDYSCH_MUTATOR_DEFS_H

#include <stdint.h>

// Common definitions for harness executables and mutator library

#define MUTATOR_ENV_NAME "__KBDYSCH_MUTATOR_SHM_ID"

typedef uint32_t mutator_shm_word;

// Mutator and harness communicate by means of dedicated SHM area.
// Assumptions:
// * Mutator should never crash, even on malformed SHM contents.
//   After all, if fuzzer finds a crash, it is quite expectably that
//   harness-writable memory can be corrupted.
// * Mutator library and harness executable should match exactly,
//   no forward/backward compatibility is assumed for now.
// * There are two different sections of SHM area: a fixed-structure section
//   and a bytecode-style section.
// * Each successful invocation of the same harness should produce the
//   same layout of fixed-structure section. It is perfectly OK for different
//   harnesses or differently-configured harness to produce different layouts
//   * this part can be parsed once during fuzzing session warm-up and then
//     pointers can be remembered
//
// Layout of SHM area:
// * Fixed-structure section: N consecutive records.
//   N and the offsets of records do not change across fuzzing session
// * MUTATOR_END_OF_FIXED_SECTION_MARK value
// * Variable-structure section: a possibly empty sequence of "instructions".
// * MUTATOR_END_OF_BYTECODE_SECTION_MARK value

enum mutator_fixed_record_type {
  MUTATOR_FIXED_RECORD_COUNTERS,
  MUTATOR_FIXED_RECORD_STRINGS,
  MUTATOR_FIXED_RECORD_STOP,
};

enum mutator_opcode {
  MUTATOR_OPCODE_SET_OFFSET,
  MUTATOR_OPCODE_STOP,
};

#define MUTATOR_END_OF_FIXED_SECTION_MARK    0xABCDDCBAu
#define MUTATOR_END_OF_BYTECODE_SECTION_MARK 0xDCBAABCDu

#pragma pack(push,1)
struct mutator_fixed_record_header {
  mutator_shm_word type;
  mutator_shm_word name_words;
  mutator_shm_word element_words;
  mutator_shm_word max_num_elements;

  mutator_shm_word num_elements_mut;
};
#pragma pack(pop)

#define MUTATOR_MAX_FIXED_RECORDS 100
#define MUTATOR_MAX_TEST_CASE_LENGTH (1 << 20)
#define MUTATOR_MAX_TRIM_OFFSETS 128
#define MUTATOR_SHM_SIZE_WORDS 1024
#define MUTATOR_SHM_SIZE (MUTATOR_SHM_SIZE_WORDS * sizeof(mutator_shm_word))

#endif  // KBDYSCH_MUTATOR_DEFS_H
