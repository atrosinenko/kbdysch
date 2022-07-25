#ifndef KBDYSCH_LOGGING_H
#define KBDYSCH_LOGGING_H

#include <stdbool.h>

enum log_category {
  LOG_GENERAL_TRACE,
  LOG_INVOKER_TRACE,
  LOG_WARNING,
  LOG_ASSERTION_FAILED,
};

struct fuzzer_state;

void disable_logs(bool disable);
void log_printf(const struct fuzzer_state *state_or_null,
                enum log_category cat, bool newline,
                const char *fmt, ...);

#define TRACE(state, ...) \
    log_printf(state, LOG_GENERAL_TRACE, true, __VA_ARGS__)
#define TRACE_NO_NL(state, ...) \
    log_printf(state, LOG_GENERAL_TRACE, false, __VA_ARGS__)
#define INVOKER_TRACE(state, ...) \
    log_printf(state, LOG_INVOKER_TRACE, true, __VA_ARGS__)
#define INVOKER_TRACE_NO_NL(state, ...) \
    log_printf(state, LOG_INVOKER_TRACE, false, __VA_ARGS__)
#define WARN(state, ...) \
    log_printf(state, LOG_WARNING, true, __VA_ARGS__)
#define LOG_FATAL(...) \
    log_printf(NULL, LOG_ASSERTION_FAILED, true, __VA_ARGS__)

#endif // KBDYSCH_LOGGING_H
