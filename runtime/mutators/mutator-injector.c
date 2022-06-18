// Usage: LD_PRELOAD=./libmutator-injector.so harness arguments < input-file.bin

#define _GNU_SOURCE
#ifdef NDEBUG
#undef NDEBUG
#endif

#define read libc_read
#include <assert.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#undef read

#define TRACE(...) fprintf(stderr, "INJECTOR: " __VA_ARGS__);

#define MAX_INPUT_LENGTH (1 << 20)
static uint8_t input_data[MAX_INPUT_LENGTH];
static size_t input_length;

void  *afl_custom_init(/*afl_state_t*/ void *afl_, unsigned int seed_);
int    afl_custom_init_trim(void *data, unsigned char *buf, size_t buf_size);
size_t afl_custom_trim     (void *data, unsigned char **out_buf);
int    afl_custom_post_trim(void *data, unsigned char success);
void   afl_custom_deinit   (void *data);

static void *mutator_state;

static ssize_t (*real_read)(int fd, void *buf, size_t size);
static bool shm_parsed;

ssize_t read(int fd, void *buf, size_t size) {
  // Parse SHM after header is initialized
  if (fd == STDIN_FILENO && !shm_parsed) {
    TRACE("Parsing SHM header");
    uint8_t *out_buf_unused;
    size_t first_length = afl_custom_trim(mutator_state, &out_buf_unused);
    assert(first_length == input_length && "Unexpected mutator?");
  }

  return real_read(fd, buf, size);
}

__attribute__((constructor))
static void constructor(void) {
  ssize_t res;
  TRACE("init\n");
  real_read = dlsym(RTLD_NEXT, "read");
  mutator_state = afl_custom_init(NULL, 0);

  res = real_read(STDIN_FILENO, input_data, MAX_INPUT_LENGTH);
  TRACE("read %zd bytes of input\n", res);
  assert(res > 0);
  input_length = res;

  int fake_stdin[2];
  res = pipe(fake_stdin);
  assert(res == 0 && "pipe");
  res = dup2(fake_stdin[0], STDIN_FILENO);
  assert(res == 0 && "dup2");
  res = write(fake_stdin[1], input_data, input_length);
  assert((size_t)res == input_length && "write");
  close(fake_stdin[0]);
  close(fake_stdin[1]);

  res = afl_custom_init_trim(mutator_state, input_data, input_length);
  assert(res == 1 && "Unexpected mutator?");

  mkdir("trimmed", 0777);

  TRACE("init done\n");
}

__attribute__((destructor))
static void destructor(void) {
  int case_number = 0;
  char output_name[32];
  uint8_t *output_buffer;

  TRACE("fini\n");

  while (!afl_custom_post_trim(mutator_state, false)) {
    sprintf(output_name, "trimmed/%03d.bin", case_number);
    size_t trimmed_length = afl_custom_trim(mutator_state, &output_buffer);
    TRACE("#%d: trimmed length = %zu -> %s\n",
          case_number, trimmed_length, output_name);
    case_number += 1;

    FILE *f = fopen(output_name, "w");
    fwrite(output_buffer, trimmed_length, 1, f);
    fclose(f);
  }

  afl_custom_deinit(mutator_state);
  TRACE("fini done\n");
}
