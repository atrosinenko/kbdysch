#ifndef DUMMY_LKL_H
#define DUMMY_LKL_H

#include <dirent.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define lkl_linux_dirent64 dirent

#define lkl_strerror strerror

struct lkl_dev_blk_ops;

struct lkl_disk {
  /* dummy */
  void *handle;
  struct lkl_dev_blk_ops *ops;
};

struct lkl_dir {
  /* dummy */
  int dummy;
};

struct lkl_statx {
  /* dummy */
  uint16_t stx_mode;
};

int lkl_disk_add(struct lkl_disk *disk);

long lkl_mount_dev(unsigned disk_id, unsigned part, const char *fs_type,
                   int flags, const char *opts,
                   char *mnt_str, unsigned mnt_str_len);

long lkl_umount_dev(unsigned disk_id, unsigned part, int flags,
                    long timeout_ms);

int lkl_mount_fs(char *fstype);

struct lkl_dir *lkl_opendir(const char *path, int *err);

struct lkl_linux_dirent64 *lkl_readdir(struct lkl_dir *dir);

int lkl_closedir(struct lkl_dir *dir);

int lkl_sys_chdir(const char *path);

int lkl_sys_mkdir(const char *path, mode_t mode);

int lkl_sys_mknodat(int dirfd, const char *path, mode_t mode, dev_t dev);

long lkl_syscall(long no, long *params);

#ifdef __cplusplus
}
#endif

#endif // DUMMY_LKL_H
