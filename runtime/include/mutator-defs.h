#ifndef KBDYSCH_MUTATOR_DEFS_H
#define KBDYSCH_MUTATOR_DEFS_H

// Common definitions for harness executables and mutator library

#define MUTATOR_ENV_NAME "__KBDYSCH_MUTATOR_SHM_ID"

#define MUTATOR_MAX_TEST_CASE_LENGTH (1 << 20)
#define MUTATOR_MAX_TRIM_OFFSETS 128
#define MUTATOR_MAX_SHM_WORDS 1024

#define MUTATOR_OP_STOP 0
#define MUTATOR_OP_TRIM_OFFSET 1

#endif  // KBDYSCH_MUTATOR_DEFS_H
