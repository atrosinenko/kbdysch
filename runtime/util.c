#include "kbdysch.h"

#include "internal-defs.h"

#include <pth.h>

static void __attribute__((constructor)) constr(void)
{
  pth_init();
}

void start_forksrv(void)
{
#ifdef __AFL_HAVE_MANUAL_CONTROL
  __AFL_INIT();
#endif
}

struct fuzzer_state *create_state(int argc, const char *argv[])
{
  struct fuzzer_state *result = calloc(1, sizeof(*result));

  result->constant_state.log_assigns = !get_bool_knob("NO_LOG", 0);

  result->current_state.rng_state = 12345678901L | 1;

  result->constant_state.native_mode = argc == 2 && (strcmp(argv[1], "native") == 0);
  result->mutable_state.file_names[0] = "";
  result->mutable_state.file_name_count = 1;

  return result;
}

int is_native_invoker(struct fuzzer_state *state)
{
  return state->constant_state.native_mode;
}

int get_bool_knob(const char *name, int default_value)
{
  return getenv(name) ? 1 : default_value;
}

int get_int_knob(const char *name, int default_value)
{
  const char *str = getenv(name);
  return str ? atoi(str) : default_value;
}

const char *get_string_knob(const char *name, const char *default_value)
{
  const char *str = getenv(name);
  return str ? str : default_value;
}


void show_help_and_exit_if_needed(int argc, const char *argv[], const char *help_message)
{
  if (argc == 1) {
    fprintf(stderr, help_message, argv[0]);
    exit(1);
  }

}

void warn_lkl_not_supported(void)
{
  fprintf(stderr, "This fuzzer is compiled without LKL support, exiting.\n");
  exit(1);
}
