#ifndef KBDYSCH_OPTIONS_H
#define KBDYSCH_OPTIONS_H

#include "kbdysch/common-defs.h"

#include <stdbool.h>
#include <stdint.h>

/// \defgroup usage_help
/// @{

#define USAGE_WITH_ARGS(args_str) "%1$s " args_str "\n"
#define USAGE_THEN_DO(descr_str)  "\t" descr_str "\n"
#define USAGE_RUN_NATIVELY \
    USAGE_WITH_ARGS("native") \
    USAGE_THEN_DO("Apply to host kernel")
#define USAGE_LKL_SIMPLE \
    USAGE_WITH_ARGS("<kernel command line>") \
    USAGE_THEN_DO  ("Run test on Linux Kernel Library")

/**
 * @brief Either continues execution or shows the help message and exits
 * @param argc         `argc` passed to `main()`
 * @param argv         `argv` passed to `main()`
 * @param help_message Help message to show if needed
 */
void show_help_and_exit_if_needed(int argc, const char *argv[], const char *help_message);

/// @}

/// \defgroup knobs Retrieving configuretion parameters
/// @{

typedef uint64_t bitmask_t;
#define BIT(n) ((bitmask_t)1 << (n))
bool get_bool_knob(const char *name, bool default_value);
bitmask_t get_bitmask_knob(const char *name, bitmask_t default_value);
int get_int_knob(const char *name, int default_value);
const char *get_string_knob(const char *name, const char *default_value);

#define DECLARE_KNOB_DEF(type, getter, name, var, default_value) \
  static type name; \
  CONSTRUCTOR(init_##name) { name = getter(var, default_value); }
#define DECLARE_BOOL_KNOB(name, var) \
  DECLARE_KNOB_DEF(bool, get_bool_knob, name, var, false)
#define DECLARE_BITMASK_KNOB(name, var) \
  DECLARE_KNOB_DEF(bitmask_t, get_bitmask_knob, name, var, 0)
#define DECLARE_INT_KNOB_DEF(name, var, default_value) \
  DECLARE_KNOB_DEF(int, get_int_knob, name, var, default_value)
#define DECLARE_INT_KNOB(name, var) \
  DECLARE_KNOB_DEF(int, get_int_knob, name, var, 0)
#define DECLARE_STRING_KNOB(name, var) \
  DECLARE_KNOB_DEF(const char *, get_string_knob, name, var, NULL)

/// @}

#endif // KBDYSCH_OPTIONS_H
