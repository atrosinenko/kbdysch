/*
 * Usage:
 *   export INJECTOR_TEST_CASE=/path/to/test-case
 *   export INJECTOR_PRINT=1 # optional
 *   LD_PRELOAD=./libmutator-injector.so harness arguments < input-file.bin
 */

#define _GNU_SOURCE
#ifdef NDEBUG
#undef NDEBUG
#endif

#include "afl-interface-decls.h"

#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define ENV_NAME_INJECTOR_PRINT     "INJECTOR_PRINT"
#define ENV_NAME_INJECTOR_TEST_CASE "INJECTOR_TEST_CASE"

#define CMD_MUTATE "[MUTATE]"

#define OUTPUT_DUMP_DIR "injector-dumped"
#define MAX_PRINT_CHARS 1024
#define MAX_OUTPUT_NAME 128
#define MAX_TEST_CASE_LENGTH (1 << 20)

#define TRACE(...) fprintf(stderr, "INJECTOR: " __VA_ARGS__);

static const char *test_case_file_name;
static uint8_t test_case_data[MAX_TEST_CASE_LENGTH];
static size_t test_case_size;

static void *mutator_state;

static void dump_output(const void *data, size_t size) {
  static int output_num = 0;
  if (getenv(ENV_NAME_INJECTOR_PRINT)) {
    static char print_buf[MAX_PRINT_CHARS + 2];
    size_t printed_length = MAX_PRINT_CHARS < size ? MAX_PRINT_CHARS : size;
    memcpy(print_buf, data, printed_length);
    if (print_buf[printed_length - 1] != '\n')
      print_buf[printed_length++] = '\n';
    print_buf[printed_length] = '\0';

    TRACE("OUTPUT #%d: BEGIN\n", output_num);
    char *cur_line = print_buf, *nl;
    while ((nl = strchr(cur_line, '\n'))) {
      *nl = '\0';
      TRACE("%s\n", cur_line);
      cur_line = nl + 1;
    }
    TRACE("OUTPUT #%d: END\n", output_num);
  } else {
    static char output_name[MAX_OUTPUT_NAME];
    sprintf(output_name, "%s/%03d.bin", OUTPUT_DUMP_DIR, output_num);

    int fd = creat(output_name, 0644);
    assert(fd >= 0 && "creat");
    write(fd, data, size);
    close(fd);

    TRACE("OUTPUT DUMPED: %s, length is %zu bytes\n", output_name, size);
  }
  output_num += 1;
}

static size_t load_file(const char *file_name, void *buf, size_t size) {
  int fd = open(file_name, O_RDONLY);
  assert(fd >= 0 && "load_file: open");
  ssize_t read_size = read(fd, buf, size);
  TRACE("Reading from %s: %zd\n", file_name, read_size);
  assert(read_size >= 0 && "load_file: read");
  close(fd);
  return (size_t)read_size;
}

static int create_stdin_writer() {
  int fds[2];
  int res;

  res = pipe(fds);
  assert(res == 0 && "pipe");
  res = dup2(fds[0], STDIN_FILENO);
  assert(res == 0 && "dup2");

  close(fds[0]);
  return fds[1];
}

__attribute__((constructor))
static void constructor(void) {
  ssize_t res;
  setvbuf(stdout, NULL, _IONBF, 0);
  TRACE("INIT\n");

  TRACE("Loading test case...\n");
  test_case_file_name = getenv(ENV_NAME_INJECTOR_TEST_CASE);
  assert(test_case_file_name && "load test case");
  test_case_size = load_file(test_case_file_name, test_case_data, MAX_TEST_CASE_LENGTH);

  if (!getenv(ENV_NAME_INJECTOR_PRINT)) {
    TRACE("Creating output directory...\n");
    mkdir(OUTPUT_DUMP_DIR, 755);
  }

  TRACE("Writing test case to stdin of harness...\n");
  int stdin_writer_fd = create_stdin_writer();
  res = write(stdin_writer_fd, test_case_data, test_case_size);
  assert((size_t)res == test_case_size && "write test case to stdin");
  close(stdin_writer_fd);

  TRACE("Initializing mutator...\n");
  mutator_state = afl_custom_init(NULL, 0);

  TRACE("INIT DONE\n");
}

static void dump_all_mutations(void) {
  TRACE("Setting test case being mutated...\n");
  unsigned pick_test_case = afl_custom_queue_get(mutator_state, test_case_file_name);
  assert(pick_test_case);
  unsigned num_outputs = afl_custom_fuzz_count(mutator_state, test_case_data, test_case_size);
  TRACE("DUMPING OUTPUTS\n");
  TRACE("Mutator requested %u mutations.\n", num_outputs);

  for (unsigned i = 0; i < num_outputs; ++i) {
    uint8_t *output_buffer;
    size_t out_size = afl_custom_fuzz(mutator_state, test_case_data, test_case_size,
                                      &output_buffer, NULL, 0, MAX_TEST_CASE_LENGTH);
    dump_output(output_buffer, out_size);
  }
}

__attribute__((destructor))
static void destructor(void) {
  TRACE("FINI\n");

  TRACE("Asking mutator to consume log...\n");
  afl_custom_queue_new_entry(mutator_state, test_case_file_name, "original_test.bin");

  if (memmem(test_case_data, test_case_size, CMD_MUTATE, strlen(CMD_MUTATE)))
    dump_all_mutations();

  TRACE("CALL DEINIT\n");
  afl_custom_deinit(mutator_state);
  TRACE("FINI DONE\n");
}
