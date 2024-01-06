#ifndef KBDYSCH_BASE_HASHING_H
#define KBDYSCH_BASE_HASHING_H

#include <memory.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define HASH_CHARS 16

typedef uint32_t fast_hash_t;

static inline fast_hash_t kbdysch_compute_fast_hash(const void *ptr, size_t length) {
  const uint8_t *data = (const uint8_t *)ptr;
  fast_hash_t result = 0;
  for (unsigned i = 0; i < length; ++i) {
    result = result * 17239u + data[i] * 17u;
  }
  return result;
}

// "out" is not zero terminated!
void kbdysch_compute_hash(char *out, const uint8_t *data, size_t size);

static inline char to_hex(unsigned n) {
  if (n < 10)
    return '0' + n;
  else
    return 'a' + (n - 10);
}

#ifdef __cplusplus
}
#endif

#endif // KBDYSCH_BASE_HASHING_H
