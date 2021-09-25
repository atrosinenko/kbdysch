#ifdef NDEBUG
#undef NDEBUG
#endif

#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define TO_KERNEL "dump_%d.fuse_to_kernel"
#define FROM_KERNEL "dump_%d.kernel_to_fuse"
#define FUSERMOUNT_CMD "fusermount -o %s -- %s"

__attribute__((aligned(4096))) char fuse_buf[4096 * 128];

int receive_fd(int sock_fd) {
  char data[256];
  char control[256];

  struct iovec data_iov = {
    .iov_base = data,
    .iov_len = sizeof(data),
  };
  struct msghdr msg = {
    .msg_iov = &data_iov,
    .msg_iovlen = 1,
    .msg_control = control,
    .msg_controllen = sizeof(control),
  };

  ssize_t res = recvmsg(sock_fd, &msg, 0);
  fprintf(stderr, "recvmsg() returned %zd\n", res);
  assert(res >= 0);

  struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
  assert(cmsg != NULL);
  assert(cmsg->cmsg_type == SCM_RIGHTS);

  int fd;
  memcpy(&fd, CMSG_DATA(cmsg), sizeof(fd));
  fprintf(stderr, "Got FD #%d\n", fd);
  return fd;
}

int mount(const char *options, const char *mount_point) {
  int res;
  int socks[2];
  char buf[32];
  res = socketpair(AF_LOCAL, SOCK_DGRAM, 0, socks);
  assert(res == 0);
  sprintf(buf, "%d", socks[0]);
  setenv("_FUSE_COMMFD", buf, 1);
  sprintf(buf, FUSERMOUNT_CMD, options, mount_point);
  res = system(buf);
  fprintf(stderr, "system() returned %d\n", res);
  assert(res == 0);

  int fd = receive_fd(socks[1]);
  close(socks[0]);
  close(socks[1]);
  return fd;
}

ssize_t read_dumped_message(const char *fmt, int index,
                            char *data, size_t size) {
  char buf[128];
  sprintf(buf, fmt, index);
  fprintf(stderr, "Loading from %s...\n", buf);
  int fd = open(buf, O_RDONLY);
  assert(fd >= 0);
  ssize_t res = read(fd, data, size);
  assert(res >= 0 && res < size /* not truncated */);
  close(fd);
  return res;
}

void fuse_read(int fuse_fd, int index) {
  static char expected_data[1024];
  ssize_t expected_res = read_dumped_message(
        FROM_KERNEL, index, expected_data, sizeof(expected_data));
  ssize_t res = read(fuse_fd, fuse_buf, sizeof(fuse_buf));
  fprintf(stderr, "FUSE read() returned %zd\n", res);
  assert(res >= 0 && res <= sizeof(fuse_buf));
  if (res != expected_res)
    fprintf(stderr, "WARN: Expected size: %zd\n", expected_res);
  else if (memcmp(fuse_buf, expected_data, res) != 0)
    fprintf(stderr, "WARN: Contents differ.\n");
}

void fuse_write(int fuse_fd, int index) {
  ssize_t length = read_dumped_message(
        TO_KERNEL, index, fuse_buf, sizeof(fuse_buf));
  ssize_t res = write(fuse_fd, fuse_buf, length);
  fprintf(stderr, "FUSE write() returned %zd\n", res);
  if (res != length)
    fprintf(stderr, "WARN: Expected %zd.\n", length);
}

int main(int argc, const char *argv[]) {
  if (argc < 4) {
    fprintf(stderr, "Usage: %s <mount point> <options> <number of messages>\n",
            argv[0]);
  }
  const char *mount_point = argv[1];
  const char *options = argv[2];
  const int num_messages = atoi(argv[3]);
  fprintf(stderr, "Mounting to %s...\n", mount_point);
  int fuse_fd = mount(options, mount_point);
  for (int i = 0; i < num_messages; ++i) {
    if (i % 2 == 0)
      fuse_read(fuse_fd, i);
    else
      fuse_write(fuse_fd, i);
  }
  return 0;
}
