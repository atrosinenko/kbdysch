#ifndef KBDYSCH_EXTDEPS_PTH_H
#define KBDYSCH_EXTDEPS_PTH_H

#include <stdbool.h>

void init_extdep_pth(void);

void spawn_thread(bool use_pthread, void *(*thread_fn)(void *), void *arg);

#endif // KBDYSCH_EXTDEPS_PTH_H
