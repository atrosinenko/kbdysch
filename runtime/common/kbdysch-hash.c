#include "kbdysch/base/hashing.h"

#include <stdio.h>
#include <unistd.h>

uint8_t buf[4096];

int main() {
  char hash[HASH_CHARS + 1];
  int length = read(0, buf, sizeof(buf));
  kbdysch_compute_hash(hash, buf, length);
  hash[HASH_CHARS] = 0;
  printf("%s\n", hash);
  return 0;
}
