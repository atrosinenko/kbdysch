#include "kbdysch/kbdysch.h"

#include "kbdysch/base/options.h"
#include "kbdysch/extdeps/pth.h"
#include "kbdysch/internal-defs.h"

#include <assert.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <signal.h>

CONSTRUCTOR(constr) {
  init_extdep_pth();
  compiler_initialize();
}

static void default_stopper_func(struct fuzzer_state *state)
{
  longjmp(state->stopper, 1);
}

void *alloc_target_pages(struct fuzzer_state *state, size_t size, int prot) {
  long result = INVOKE_SYSCALL(state, mmap, (long)NULL, size, prot,
                               (long)(MAP_PRIVATE | MAP_ANONYMOUS), (long)-1, (long)0);
  return (void *)result;
}

void start_forksrv(void)
{
  fprintf(stderr, "Ready to start the fork server.\n");
#ifdef __AFL_HAVE_MANUAL_CONTROL
  __AFL_INIT();
#endif

  // Basically for usage with afl-tmin on hanging inputs
  int limit = get_int_knob("TIME_LIMIT", -1);
  if (limit > 0) {
    struct itimerspec tval;
    struct sigevent sigev;
    memset(&tval, 0, sizeof(tval));
    memset(&sigev, 0, sizeof(sigev));
    sigev.sigev_notify = SIGEV_SIGNAL;
    sigev.sigev_signo = SIGKILL;
    tval.it_value.tv_sec = limit / 1000;
    tval.it_value.tv_nsec = (limit % 1000) * 1000000;
    timer_t timer_id;
    CHECK_THAT(timer_create(CLOCK_MONOTONIC, &sigev, &timer_id) == 0);
    CHECK_THAT(timer_settime(timer_id, 0, &tval, NULL) == 0);
  }
}

static const char *known_strings[] = { "" /* empty */ };

struct fuzzer_state *create_state(int argc, const char *argv[], stopper_func_t stopper_func)
{
  struct fuzzer_state *result = calloc(1, sizeof(*result));

  result->stopper_func = stopper_func ? stopper_func : default_stopper_func;
  result->constant_state.log_assigns = !get_bool_knob("NO_LOG", false);

  result->current_state.rng_state = 12345678901L | 1;

  result->constant_state.native_mode = argc == 2 && (strcmp(argv[1], "native") == 0);
  result->mutable_state.file_names[0] = "";
  result->mutable_state.file_basenames[0] = "";
  result->current_state.file_name_count = 1;

  for (int i = 0; i < sizeof(known_strings) / sizeof(known_strings[0]); ++i) {
    res_add_to_known_strings(result, known_strings[i]);
  }

  return result;
}

// A kludgy quick-fix for link-time assertions in LKL :)
//
// Every harness invokes create_state() function, thus pulling
// this object in.
#if 1
void __generic_xchg_called_with_bad_pointer() { abort(); }
void wrong_size_cmpxchg() { abort(); }
#endif

void stop_processing(struct fuzzer_state *state) {
  state->stopper_func(state);
}

bool is_native_invoker(const struct fuzzer_state *state)
{
  return state->constant_state.native_mode;
}

int get_num_errors_returned(const struct fuzzer_state *state) {
  return state->current_state.num_errors_returned;
}

bool syscalls_inhibited(const struct fuzzer_state *state) {
  return state->mutable_state.syscalls_inhibited;
}

void inhibit_syscalls(struct fuzzer_state *state, bool inhibited) {
  state->mutable_state.syscalls_inhibited = inhibited;
}

void warn_lkl_not_supported(void)
{
  fprintf(stderr, "This fuzzer is compiled without LKL support, exiting.\n");
  exit(1);
}

void dump_to_file(const char *dump_file_name, const void *data, size_t size)
{
  fprintf(stderr, "Dumping to %s... ", dump_file_name);

  unlink(dump_file_name);
  int dump_fd = open(dump_file_name, O_CREAT | O_WRONLY, S_IRUSR);
  CHECK_THAT(dump_fd >= 0);
  CHECK_THAT(write(dump_fd, data, size) == size);
  close(dump_fd);
  fprintf(stderr, "OK\n");
}

void show_help_and_exit_if_needed(int argc, const char *argv[], const char *help_message) {
  if (argc == 1) {
    fprintf(stderr, help_message, argv[0]);
    exit(1);
  }
}
