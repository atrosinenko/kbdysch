#include "kbdysch/hashing.h"

void kbdysch_compute_hash(char *out, const uint8_t *data, size_t size) {
  const uint64_t MULT = UINT64_C(1000000007);
  uint64_t result = 1;
  for (unsigned i = 0; i < size; i += 8) {
    unsigned slice_bytes = (i + 8 < size) ? 8 : (size - i);
    uint64_t slice = 0;
    memcpy(&slice, &data[i], slice_bytes);
    result = result * MULT + slice;
  }
  for (unsigned i = 0; i < HASH_CHARS; ++i)
    out[i] = to_hex((result >> (i * 4)) & 0xf);
}
