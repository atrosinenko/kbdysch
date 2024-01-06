#ifndef KBDYSCH_BASE_BASE_DEFS_H
#define KBDYSCH_BASE_BASE_DEFS_H

#define CONSTRUCTOR(unique_name) \
  static void __attribute__((constructor)) unique_name(void)

#endif // KBDYSCH_BASE_BASE_DEFS_H
