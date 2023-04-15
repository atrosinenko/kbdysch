#ifndef DUMMY_LKL_HOST_H
#define DUMMY_LKL_HOST_H

#include "lkl.h"

#include <sys/uio.h>

#ifdef __cplusplus
extern "C" {
#endif

struct lkl_blk_req {
  /* dummy */
  unsigned type;
  unsigned long long sector;
  struct iovec *buf;
  int count;
};

struct lkl_dev_blk_ops {
  /* dummy */
  int (*get_capacity)(struct lkl_disk disk, unsigned long long *res);
  int (*request)(struct lkl_disk disk, struct lkl_blk_req *req);
};

#define LKL_DEV_BLK_TYPE_READ      0
#define LKL_DEV_BLK_TYPE_WRITE     1
#define LKL_DEV_BLK_TYPE_FLUSH     4
#define LKL_DEV_BLK_TYPE_FLUSH_OUT 5

#define LKL_DEV_BLK_STATUS_OK    0
#define LKL_DEV_BLK_STATUS_IOERR 1
#define LKL_DEV_BLK_STATUS_UNSUP 2

struct lkl_host_operations {
  /* dummy */
  void (*print)(const char *str, int len);
  void (*panic)(void);
};
extern struct lkl_host_operations lkl_host_ops;

int lkl_init(struct lkl_host_operations *lkl_ops);
int lkl_start_kernel(const char *cmd_line, ...);

#ifdef __cplusplus
}
#endif

#endif // DUMMY_LKL_HOST_H
