#ifndef KBDYSCH_HASHING_H
#define KBDYSCH_HASHING_H

#include <memory.h>
#include <stdint.h>

#define HASH_CHARS 16

// "out" is not zero terminated!
void kbdysch_compute_hash(char *out, const uint8_t *data, size_t size);

static inline char to_hex(unsigned n) {
  if (n < 10)
    return '0' + n;
  else
    return 'a' + (n - 10);
}

#endif // KBDYSCH_HASHING_H
