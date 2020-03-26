#ifndef COMPILER_H
#define COMPILER_H

/**
 * @file This header is a single place for local instrumenter-specific adjustments.
 */

/// \defgroup lkl-entry Notification of instrumenter about LKL syscall enter/exit (may not cover all communications)
/// @{

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

#endif // COMPILER_H
