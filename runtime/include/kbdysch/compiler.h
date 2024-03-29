#ifndef KBDYSCH_COMPILER_H
#define KBDYSCH_COMPILER_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file This header is a single place for local instrumenter-specific adjustments.
 */

/// \defgroup lkl-entry Notification of instrumenter about LKL syscall enter/exit (may not cover all communications)
/// @{

/// Mark values with length semantics for symbolic execution, etc.
static inline uint64_t compiler_length_value(uint64_t length)
{
  return length;
}

static inline void compiler_initialize(void)
{

}

static inline void compiler_enter_lkl(void)
{

}

static inline void compiler_exit_lkl(void)
{

}

/// @}

#ifdef __cplusplus
}
#endif

#endif // KBDYSCH_COMPILER_H
