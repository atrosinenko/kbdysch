#include "kbdysch/base/options.h"
#include "kbdysch/input.h"
#include "kbdysch/kbdysch.h"
#include "kbdysch/invoker-utils.h"
#include "kbdysch/mutator-interface.h"

#include <fcntl.h>
#include <linux/fuse.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <syscall.h>
#include <pth.h>

#if FUSE_KERNEL_VERSION != 7
#error Unexpected FUSE_KERNEL_VERSION
#endif
#if FUSE_KERNEL_MINOR_VERSION < 32
// FIXME Implement a better solution
#warning Some structure fields are excluded from fuzzing
#define FUSE_COMPAT
#endif

DECLARE_BOOL_KNOB(as_root, "AS_ROOT")
DECLARE_BOOL_KNOB(dump_fuse, "DUMP")

#define MAX_OPS 32
#define BUF_SIZE (1 << 16)
#define FUSE_MOUNT_POINT "/fuse-mnt"
#define FUSE_MOUNT_OPTIONS "fd=%d,rootmode=40000,user_id=%d,group_id=0"
#define FUSE_DEVICE_SYSFS_PATH "devices/virtual/misc/fuse"

#define DUMP_TO_KERNEL "dump_%d.fuse_to_kernel"
#define DUMP_FROM_KERNEL "dump_%d.kernel_to_fuse"

static int fuse_fd;
static uint8_t *kernel_to_fuse_buffer;
static uint8_t *fuse_to_kernel_buffer;
static int fuse_request_counter;

struct handler_args {
  int in_out_length;
  const uint8_t *request;
};

typedef void (*handler_fn)(struct fuzzer_state *state, uint8_t *data,
                           struct handler_args *args);
struct request_handler {
  int reply_length; // Negative if unknown
  handler_fn handler;
};

#define FUSE_DEFAULT_HANDLER 63
#define NUM_OPCODES (FUSE_DEFAULT_HANDLER + 1)
static struct request_handler handlers[NUM_OPCODES];

static void dump_if_requested(bool to_kernel, void *data, size_t length) {
  static char file_name[128];
  if (dump_fuse) {
    sprintf(file_name, to_kernel ? DUMP_TO_KERNEL : DUMP_FROM_KERNEL, fuse_request_counter);
    dump_to_file(file_name, data, length);
  }
}

static bool fill_fuse_reply(struct fuzzer_state *state,
                            const uint8_t *data_in, long size_in,
                            uint8_t *data_out, long *size_out) {
  const struct fuse_in_header *in_header =
      (const struct fuse_in_header *) data_in;
  struct fuse_out_header *out_header = (struct fuse_out_header *) data_out;
  uint8_t *payload_out = data_out + sizeof(struct fuse_out_header);

  if (in_header->opcode >= NUM_OPCODES) {
    fprintf(stderr, "Invalid opcode requested by kernel: %1$u/0x%1$x\n",
            in_header->opcode);
    abort();
  }
  uint16_t control = res_get_u16(state);
  int fuse_answer_len = 0;
  int fuse_err;
  uint64_t fuse_unique = (control & 0xf000) == 0 ? res_get_u64(state) : in_header->unique;
  if ((control & 0x0f00) == 0) {
    fuse_err = (int16_t)res_get_u16(state);
    if (!fuse_err) {
      fuse_answer_len = control & 0x00ff;
      res_copy_bytes(state, payload_out, fuse_answer_len);
    }
  } else {
    fuse_err = (control & 0x00f0) == 0 ? (int16_t)res_get_u16(state) : 0;
    if (!fuse_err) {
      struct request_handler *handler = &handlers[in_header->opcode];
      if (!handler->handler)
        handler = &handlers[FUSE_DEFAULT_HANDLER];
      struct handler_args args = {
        .in_out_length = handler->reply_length,
        .request = data_in + sizeof(struct fuse_in_header),
      };
      handler->handler(state, payload_out, &args);
      fuse_answer_len = args.in_out_length;
    }
  }

  if (fuse_answer_len < 0)
    return false;
  *size_out = sizeof(struct fuse_out_header) + fuse_answer_len;
  out_header->error = fuse_err;
  out_header->len = *size_out;
  out_header->unique = fuse_unique;
  return true;
}

static void process_fuse_request(struct fuzzer_state *state) {
  struct fuse_in_header *in_header = (struct fuse_in_header*) kernel_to_fuse_buffer;
  struct fuse_out_header *out_header = (struct fuse_out_header *) fuse_to_kernel_buffer;
  int res;

  struct pollfd pfd = {
    .fd = fuse_fd,
    .events = POLLIN,
  };
  struct timespec ts = {
    .tv_sec = 0,
    .tv_nsec = 100000000,
  };
  res = CHECKED_SYSCALL(state, ppoll, (long)&pfd, (long)1, (long)&ts, (long)NULL);
  if (res == 0) {
    pth_yield(NULL);
    return;
  }
  fprintf(stderr, "FUSE: reading...\n");
  res = INVOKE_SYSCALL(state, read, fuse_fd, (long)kernel_to_fuse_buffer, BUF_SIZE);
  uint32_t opcode_from_kernel = in_header->opcode;
  fprintf(stderr, "FUSE: #%d read() returned %d (opcode = 0x%x)\n",
          fuse_request_counter, res, opcode_from_kernel);
  dump_if_requested(false, kernel_to_fuse_buffer, res);
  ++fuse_request_counter;

  long size_out;
  if (!fill_fuse_reply(state, kernel_to_fuse_buffer, res,
                       fuse_to_kernel_buffer, &size_out)) {
    fprintf(stderr, "FUSE: not sending reply.\n");
    return;
  }
  dump_if_requested(true, fuse_to_kernel_buffer, size_out);
  ++fuse_request_counter;

  res = INVOKE_SYSCALL(state, write, fuse_fd, (long)fuse_to_kernel_buffer, size_out);
  if (res < 0)
    fprintf(stderr, "FUSE: did not accept write() of %ld bytes: %s, guessing correct length...\n",
            size_out, STRERROR(state, res));
  for (int i = 0; res < 0 && i < 1024; i += 1) {
    size_out = sizeof(struct fuse_out_header) + i;
    out_header->len = size_out;
    res = INVOKE_SYSCALL(state, write, fuse_fd, (long)fuse_to_kernel_buffer, size_out);
  }
  fprintf(stderr, "FUSE: #%d write() of %ld bytes returned %d: %s\n",
          fuse_request_counter - 1, size_out, res, STRERROR_OR_POSITIVE(state, res));

  if (res < 0) {
    fprintf(stderr, "Exiting\n");
    stop_processing(state);
  }
}

static void *fuse_thread_fn(void *arg) {
  struct fuzzer_state *state = (struct fuzzer_state *)arg;
  for (;;)
    process_fuse_request(state);
  return NULL;
}

static void mount_fuse(struct fuzzer_state *state, int uid) {
  fuse_fd = kernel_open_device_by_sysfs_name(state, "fuse_dev", FUSE_DEVICE_SYSFS_PATH, S_IFCHR);
  set_fd_guard(state, fuse_fd);
  fprintf(stderr, "FUSE fd = %d\n", fuse_fd);

  CHECKED_SYSCALL(state, mkdirat, AT_FDCWD, (long)FUSE_MOUNT_POINT, 040777);

  static char fuse_opts[4096];
  sprintf(fuse_opts, FUSE_MOUNT_OPTIONS, fuse_fd, uid);
  CHECKED_SYSCALL(state, mount, (long)"fuse_test",
                  (long)FUSE_MOUNT_POINT, (long)"fuse.test",
                  MS_NOSUID | MS_NODEV, (long)fuse_opts);
  fprintf(stderr, "FUSE mount succeded.\n");

  const int prot = PROT_READ | PROT_WRITE;
  kernel_to_fuse_buffer = alloc_target_pages(state, BUF_SIZE, prot);
  fuse_to_kernel_buffer = alloc_target_pages(state, BUF_SIZE, prot);
  fprintf(stderr, "Target pages allocated: %p / %p\n",
          kernel_to_fuse_buffer, fuse_to_kernel_buffer);
}

int main(int argc, const char *argv[]) {
  show_help_and_exit_if_needed(
        argc, argv,
        USAGE_RUN_NATIVELY
        USAGE_LKL_SIMPLE
        );

  struct fuzzer_state *state = create_state(argc, argv, NULL);
  mutator_init();
  const int uid = as_root ? 0 : 1;

  kernel_configure_diskless(state, FUSE_MOUNT_POINT);
  if (!is_native_invoker(state))
    kernel_boot(state, argv[1]);
  mount_fuse(state, uid);
  if (uid)
    INVOKE_SYSCALL(state, setreuid, uid, 1);
  res_load_whole_stdin(state);

  if (setjmp(*res_get_stopper_env(state)) == 0) {
    process_fuse_request(state);
    spawn_thread(state, fuse_thread_fn, state);
    pth_yield(NULL);

    for (int block_index = 0; block_index < MAX_OPS; ++block_index) {
      res_mark_section_start(state);

      if (block_index > fuse_request_counter + 2)
        break;

      exit_if_too_many_errors(state);
      skip_block_if_requested(state, block_index);
      size_t decoded_bytes = do_invoke(state, block_index, invoke_next_op);
      align_next_block(state, block_index, decoded_bytes);
      pth_yield(NULL);
    }
  }
  print_summary_at_exit(state);

  return 0;
}

#define DEFINE_HANDLER(name) \
    static void name(struct fuzzer_state *state, uint8_t *data, \
                     struct handler_args *args)

#define FILL_STRUCT(name) \
    DEFINE_HANDLER(fill_##name) { \
      struct name *res = (struct name *) data; \
      memset(res, 0, sizeof(*res));

#define GET_REQUEST_FIELD(struct_name, field) \
    (((struct struct_name *) args->request)->field)
#define FILL_SMALL_I64(var) var = (int64_t)(int8_t)res_get_u8(state)
#define FILL_ERRNO(var) (var = (int16_t)res_get_u16(state))

FILL_STRUCT(fuse_init_out)
  FILL_SMALL_I64(res->major);
  FILL_SMALL_I64(res->minor);
  FILL_SMALL_I64(res->max_readahead);
  FILL_SMALL_I64(res->max_background);
  FILL_SMALL_I64(res->congestion_threshold);
  FILL_SMALL_I64(res->max_write);
  FILL_SMALL_I64(res->time_gran);
#ifndef FUSE_COMPAT
  FILL_SMALL_I64(res->max_pages);
  FILL_SMALL_I64(res->map_alignment);
  res->flags = res_get_u32(state);
#endif
}

FILL_STRUCT(fuse_attr)
  FILL_SMALL_I64(res->ino);
  FILL_SMALL_I64(res->atime);
  FILL_SMALL_I64(res->mtime);
  FILL_SMALL_I64(res->ctime);
  FILL_SMALL_I64(res->atimensec);
  FILL_SMALL_I64(res->mtimensec);
  FILL_SMALL_I64(res->ctimensec);
  FILL_SMALL_I64(res->nlink);
  FILL_SMALL_I64(res->uid);
  FILL_SMALL_I64(res->gid);
  FILL_SMALL_I64(res->rdev);
  FILL_SMALL_I64(res->blksize);
  res->size = res_get_u16(state);
  res->blocks = res_get_u16(state);
  res->mode = res_get_u32(state);
#ifndef FUSE_COMPAT
  res->flags = res_get_u32(state);
#endif
}

FILL_STRUCT(fuse_entry_out)
  FILL_SMALL_I64(res->nodeid);
  FILL_SMALL_I64(res->generation);
  FILL_SMALL_I64(res->entry_valid);
  FILL_SMALL_I64(res->attr_valid);
  FILL_SMALL_I64(res->entry_valid_nsec);
  FILL_SMALL_I64(res->attr_valid_nsec);
  fill_fuse_attr(state, data + 40, args);
}

FILL_STRUCT(fuse_attr_out)
  FILL_SMALL_I64(res->attr_valid);
  FILL_SMALL_I64(res->attr_valid_nsec);
  fill_fuse_attr(state, data + 16, args);
}

FILL_STRUCT(fuse_write_out)
  FILL_ERRNO(res->size);
  if (res->size & 0x4000)
    res->size = GET_REQUEST_FIELD(fuse_write_in, size);
}

FILL_STRUCT(fuse_kstatfs)
  FILL_SMALL_I64(res->blocks);
  FILL_SMALL_I64(res->bfree);
  FILL_SMALL_I64(res->bavail);
  FILL_SMALL_I64(res->files);
  FILL_SMALL_I64(res->ffree);
  FILL_SMALL_I64(res->bsize);
  FILL_SMALL_I64(res->namelen);
  FILL_SMALL_I64(res->frsize);
}

FILL_STRUCT(fuse_statfs_out)
  fill_fuse_kstatfs(state, data, args);
}

DEFINE_HANDLER(fill_raw) {
  if (args->in_out_length < 0)
    return;
  res_copy_bytes(state, data, args->in_out_length);
}

#define FIXED_STRUCT(opcode, name) \
  [opcode] = { sizeof(struct name), fill_##name }
#define NO_REPLY(opcode) \
  [opcode] = { -1, fill_raw }
#define EMPTY_REPLY(opcode) \
  [opcode] = { 0, fill_raw }
#define DEFAULT_STRUCT(opcode, name) \
  [opcode] = { sizeof(struct name), fill_raw }

static struct request_handler handlers[] = {
  FIXED_STRUCT(FUSE_LOOKUP, fuse_entry_out),
  NO_REPLY(FUSE_FORGET),
  FIXED_STRUCT(FUSE_GETATTR, fuse_attr_out),
  DEFAULT_STRUCT(FUSE_OPEN, fuse_open_out),
  EMPTY_REPLY(FUSE_READ),
  DEFAULT_STRUCT(FUSE_WRITE, fuse_write_out),
  FIXED_STRUCT(FUSE_STATFS, fuse_statfs_out),
  DEFAULT_STRUCT(FUSE_GETXATTR, fuse_getxattr_out),
  DEFAULT_STRUCT(FUSE_BMAP, fuse_bmap_out),
  DEFAULT_STRUCT(FUSE_IOCTL, fuse_ioctl_out),
  DEFAULT_STRUCT(FUSE_POLL, fuse_poll_out),
  DEFAULT_STRUCT(FUSE_LSEEK, fuse_lseek_out),

  FIXED_STRUCT(FUSE_INIT, fuse_init_out),
  EMPTY_REPLY(FUSE_DEFAULT_HANDLER),
};
