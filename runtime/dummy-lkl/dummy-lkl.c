#include "lkl.h"
#include "lkl_host.h"

#include <stdbool.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <time.h>

static char timestamp_mark(void) {
  // Ensure dummy-lkl behaves unstably without fake_time, just like LKL does.
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  unsigned x = 0;
  x += (unsigned)ts.tv_sec * 3U;
  x += (unsigned)ts.tv_nsec / 17U;
  x &= 1023;
  if (x < 10)
    return '/';
  else if (x < 100)
    return '*';
  else if (x < 500)
    return '-';
  else
    return '|';
}

#define PRINT_MESSAGE(args_fmt, ...) \
    fprintf(stderr, "%c DUMMY LKL: %s(" args_fmt ")\n", timestamp_mark(), __func__, __VA_ARGS__)
#define PRINT_MESSAGE0() \
    fprintf(stderr, "%c DUMMY LKL: %s()\n", timestamp_mark(), __func__)

struct lkl_host_operations lkl_host_ops;

int lkl_disk_add(struct lkl_disk *disk) {
  static int next_id = 0;
  PRINT_MESSAGE("ret <- %d", next_id);
  return next_id++;
}

long lkl_mount_dev(unsigned disk_id, unsigned part, const char *fs_type, int flags,
                   const char *opts, char *mnt_str, unsigned mnt_str_len) {
  PRINT_MESSAGE("disk_id=%u, part=%u, fs_type=%s, flags=0x%x, opts=%s",
                disk_id, part, fs_type, flags, opts);
  return 0;
}

long lkl_umount_dev(unsigned disk_id, unsigned part, int flags,
                    long timeout_ms) {
  PRINT_MESSAGE("disk_id=%u, part=%u, flags=0x%x",
                disk_id, part, flags);
  return 0;
}

int lkl_start_kernel(struct lkl_host_operations *lkl_ops, const char *cmd_line, ...) {
  PRINT_MESSAGE("cmd_line=%s", cmd_line);
  return 0;
}

int lkl_mount_fs(char *fstype) {
  PRINT_MESSAGE("fstype=%s", fstype);
  return 0;
}

struct lkl_dir *lkl_opendir(const char *path, int *err) {
  static struct lkl_dir dummy_dir;
  PRINT_MESSAGE("path=%s", path);
  *err = 0;
  return &dummy_dir;
}

struct lkl_linux_dirent64 *lkl_readdir(struct lkl_dir *dir) {
  PRINT_MESSAGE0();
  return NULL;
}

int lkl_closedir(struct lkl_dir *dir) {
  PRINT_MESSAGE0();
  return 0;
}

int lkl_sys_chdir(const char *path) {
  PRINT_MESSAGE("path=%s", path);
  return 0;
}

int lkl_sys_mkdir(const char *path, mode_t mode) {
  PRINT_MESSAGE("path=%s, mode=0x%x", path, (int)mode);
  return 0;
}

int lkl_sys_mknodat(int dirfd, const char *path, mode_t mode, dev_t dev) {
  PRINT_MESSAGE("dirfd=%d, path=%s, mode=0x%x, dev=0x%x",
                dirfd, path, (int)mode, (int)dev);
  return 0;
}

bool starts_with(const char *a, const char *b) {
  size_t length = strlen(b);
  return 0 == strncmp(a, b, length);
}

#define FD_FAKE_SYSFS_DEV 42
#define FAKE_SYSFS_CONTENTS "12:34"

long lkl_syscall(long no, long *params) {
  PRINT_MESSAGE("no=%ld, params={0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx}",
                no, params[0], params[1], params[2], params[3], params[4], params[5]);
  switch (no) {
  case __NR_openat:
    if (starts_with((char *) params[1], "/sysfs/"))
      return FD_FAKE_SYSFS_DEV;
    break;
  case __NR_read:
    if (params[0] == FD_FAKE_SYSFS_DEV && params[2] >= strlen(FAKE_SYSFS_CONTENTS)) {
      strcpy((char *) params[1], FAKE_SYSFS_CONTENTS);
      return strlen(FAKE_SYSFS_CONTENTS);
    }
    return params[2];
  case __NR_write:
  case __NR_pwrite64:
    return params[2];
  }

  return 0;
}
