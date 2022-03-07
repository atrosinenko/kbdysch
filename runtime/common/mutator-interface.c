#include "mutator-interface.h"
#include "mutator-defs.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/shm.h>

static bool initialized;
static uint32_t *shm_words;
static unsigned current_word;

void mutator_init(void) {
  const char *shm_str = getenv(MUTATOR_ENV_NAME);
  if (!shm_str)
    return;

  shm_words = shmat(atoi(shm_str), NULL, 0);
  if (!shm_words)
    return;

  initialized = true;
  current_word = 0;
}

void mutator_write_trim_offset(unsigned offset) {
  if (!initialized)
    return;

  if (current_word + 2 >= MUTATOR_MAX_SHM_WORDS)
    return;  // Too many offsets

  shm_words[current_word + 0] = MUTATOR_OP_TRIM_OFFSET;
  shm_words[current_word + 1] = offset;
  shm_words[current_word + 2] = MUTATOR_OP_STOP;  // To be overwritten

  current_word += 2;  // Buffer was extended by only *two* words
}
