#ifndef KBDYSCH_COMMON_DEFS_H
#define KBDYSCH_COMMON_DEFS_H

#include "kbdysch/base/base-defs.h"

// Hack preventing LKL's BPF definitions from interfering with host ones
#define __LKL__LINUX_BPF_H__
union lkl_bpf_attr;

#include <stdbool.h>
#include <stdint.h>
#include <memory.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LKL_HAS_STATX_SYSCALL 1

#define MAX_PART_COUNT 10

#define MAX_INPUT_LEN (1 << 16)
#define MAX_BUFFER_LEN (1 << 20)
#define MAX_FILE_NAME_LEN (1 << 16)
#define MAX_STRING_LEN (1 << 16)

// Put N predefined bytes right after the allocated buffer
#define WATERMARK_SIZE 32

struct fuzzer_state;

typedef char filename_t[MAX_FILE_NAME_LEN];
typedef char string_t[MAX_STRING_LEN];
typedef uint8_t buffer_t[MAX_BUFFER_LEN + WATERMARK_SIZE];

// For raw buffers that could possibly contain aligned structures
#define ALIGNED_ENOUGH __attribute__((aligned(64)))

#ifdef __cplusplus
}
#endif

#endif // KBDYSCH_COMMON_DEFS_H
