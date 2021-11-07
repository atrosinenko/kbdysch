#include "kbdysch.h"
#include "internal-defs.h"

#include <stdarg.h>

#define MAX_LINE_LENGTH 256
#define MAX_EXTRA_LENGTH 32

static bool logging_is_disabled = false;

void disable_logs(bool disable) {
  logging_is_disabled = disable;
}

static bool log_category_enabled(const struct fuzzer_state *state_or_null,
                                 enum log_category cat) {
  switch (cat) {
  case LOG_ASSERTION_FAILED:
    return true;
  case LOG_INVOKER_TRACE:
    if (state_or_null && !state_or_null->constant_state.log_assigns)
      return false;
    if (state_or_null && state_or_null->mutable_state.syscalls_inhibited)
      return false;
    break;
  default:
    break;
  }

  return !logging_is_disabled;
}

static void log_vprintf(const struct fuzzer_state *state_or_null,
                        enum log_category cat, bool newline,
                        const char *fmt, va_list ap) {
  if (!log_category_enabled(state_or_null, cat))
    return;

  char buffer[MAX_LINE_LENGTH + MAX_EXTRA_LENGTH];

  int length = vsnprintf(buffer, MAX_LINE_LENGTH, fmt, ap);
  // `length` is to-be-written length
  if (length > MAX_LINE_LENGTH)
    length = MAX_LINE_LENGTH;
  // Now `length` is the actual length of the string
  buffer[length] = '\0';
  if (length == MAX_LINE_LENGTH)
    strcat(&buffer[length], "<truncated>");
  if (newline)
    strcat(&buffer[length], "\n");

  fputs(buffer, stderr);
}

void log_printf(const struct fuzzer_state *state_or_null,
                enum log_category cat, bool newline,
                const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  log_vprintf(state_or_null, cat, newline, fmt, ap);
  va_end(ap);
}
