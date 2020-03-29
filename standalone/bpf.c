// An example program to load eBPF socket filter into the kernel and execute it

#define _GNU_SOURCE

#include <stdint.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <syscall.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/bpf.h>
#include <signal.h>

union bpf_attr attr;
char prog_data[1024];
char buf[128];
char log_buf[65536];

int main(int argc, char *argv)
{
  int socks[2];

  setreuid(1000, 1000);

  attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
  attr.license   = (uint64_t) "GPL";
  attr.log_buf   = (uint64_t) log_buf;
  attr.log_size  = sizeof(log_buf);
  attr.log_level = 5;

  ssize_t length = read(STDIN_FILENO, prog_data, sizeof(prog_data));
  attr.insn_cnt = length / 8;
  attr.insns    = (uint64_t) prog_data;

  int bpffd = syscall(SYS_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
  fprintf(stderr, "%s\n", log_buf);

  socketpair(AF_UNIX, SOCK_DGRAM, 0, socks);
  setsockopt(socks[0], SOL_SOCKET, SO_ATTACH_BPF, &bpffd, sizeof(bpffd));

  raise(SIGSTOP);

  send(socks[1], buf, sizeof(buf), 0);
  recv(socks[0], buf, sizeof(buf), 0);

  return 0;
}
