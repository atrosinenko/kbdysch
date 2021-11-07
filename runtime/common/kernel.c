#include "kbdysch.h"

#include "internal-defs.h"
#include "invoker-utils.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/sysmacros.h>
#include <syscall.h>
#include <ctype.h>

DECLARE_BOOL_KNOB(dump_parts, "DUMP")
DECLARE_BOOL_KNOB(read_only, "READ_ONLY")
DECLARE_BOOL_KNOB(no_printk, "NO_PRINTK")
DECLARE_BOOL_KNOB(exit_on_oom, "EXIT_ON_OOM")
DECLARE_BOOL_KNOB(no_patch, "NO_PATCH")
DECLARE_BITMASK_KNOB(no_bad_words, "NO_BAD_WORDS")
DECLARE_STRING_KNOB(mount_options_knob, "MOUNT_OPTIONS")

#ifdef USE_LKL

// Unfortunately, printk does not have `state` argument...
static bool patching_was_performed = false;

static bool boot_complete = false;

static void kernel_dump_all_pertitions_if_requested(struct fuzzer_state *state)
{
  if (!dump_parts)
    return;

  for (int part = 0; part < state->constant_state.part_count; ++part) {
    char dump_file_name[128];
    snprintf(dump_file_name, sizeof(dump_file_name), "dump_%s.img",
             state->partitions[part].fstype);

    dump_to_file(dump_file_name, state->partitions[part].data, state->partitions[part].size);
  }
}

static void set_part_to_disk(struct lkl_disk *disk, partition_t *partition)
{
  disk->handle = partition;
}

static partition_t *part_from_disk(struct lkl_disk disk)
{
  return (partition_t *)disk.handle;
}

static int mem_get_capacity(struct lkl_disk disk, unsigned long long *res) {
  *res = part_from_disk(disk)->size;
  return LKL_DEV_BLK_STATUS_OK;
}

static int mem_request(struct lkl_disk disk, struct lkl_blk_req *req)
{
  int reading_requested;
  switch(req->type) {
    case LKL_DEV_BLK_TYPE_READ:
      reading_requested = 1;
      break;
    case LKL_DEV_BLK_TYPE_WRITE:
      reading_requested = 0;
      break;
    case LKL_DEV_BLK_TYPE_FLUSH:
    case LKL_DEV_BLK_TYPE_FLUSH_OUT:
      // no-op
      return LKL_DEV_BLK_STATUS_OK;
    default:
      return LKL_DEV_BLK_STATUS_UNSUP;
  }

  partition_t * const partition = part_from_disk(disk);
  size_t offset = req->sector * 512;

  if (offset >= partition->size)
      return LKL_DEV_BLK_STATUS_IOERR;

  for (int i = 0; i < req->count; ++i)
  {
    size_t len = req->buf[i].iov_len;
    if (offset + len > partition->size)
      return LKL_DEV_BLK_STATUS_IOERR;

    partition->off_start[partition->off_cur] = offset;
    partition->off_end  [partition->off_cur] = offset + len;
    partition->off_cur++;
    if (partition->off_cur >= ACCESS_HISTORY_LEN)
      partition->off_cur = 0;
    partition->access_count++;

    if (reading_requested)
      memcpy(req->buf[i].iov_base, partition->data + offset, len);
    else
      memcpy(partition->data + offset, req->buf[i].iov_base, len);
    offset += len;
  }
  return LKL_DEV_BLK_STATUS_OK;
}

void kernel_setup_disk(struct fuzzer_state *state, const char *filename, const char *fstype)
{
  partition_t *partition = &state->partitions[state->constant_state.part_count];

  set_part_to_disk(&partition->disk, partition);

  int image_fd = open(filename, O_RDONLY);
  if(image_fd == -1) {
    LOG_FATAL("Cannot open '%s': %s", filename, strerror(errno));
    abort();
  }

  off_t size = lseek(image_fd, 0, SEEK_END);
  if (size == (off_t)-1) {
    perror("setup_disk: cannot get disk size");
    abort();
  }

  partition->size = size;
  strncpy(partition->fstype, fstype, sizeof(partition->fstype));

  // First, try with HugeTLB enabled to speed up forkserver
  TRACE_NO_NL(state, "Loading %s with HugeTLB... ", filename);
  partition->data = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, -1, 0);
  if (partition->data != MAP_FAILED) {
    TRACE(state, "OK");
    CHECK_THAT(pread(image_fd, partition->data, size, 0) == size);
  } else {
    WARN(state, "Cannot load %s with HugeTLB: %s", filename, strerror(errno));
    TRACE_NO_NL(state, "Loading %s without HugeTLB... ", filename);
    partition->data = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE, image_fd, 0);
    if (partition->data == MAP_FAILED) {
      LOG_FATAL("Cannot load %s: %s", filename, strerror(errno));
      abort();
    } else {
      TRACE(state, "OK");
    }
  }
  close(image_fd);

  state->constant_state.part_count += 1;
}


static void add_all_disks(struct fuzzer_state *state)
{
  static struct lkl_dev_blk_ops blk_ops;
  blk_ops.get_capacity = mem_get_capacity;
  blk_ops.request = mem_request;

  if (state->constant_state.diskless) {
    return;
  }

  for (int i = 0; i < state->constant_state.part_count; ++i)
  {
    state->partitions[i].disk.ops = &blk_ops;
    int disk_id = lkl_disk_add(&state->partitions[i].disk);
    CHECK_THAT(disk_id >= 0);
    state->partitions[i].disk_id = disk_id;
  }
}

static void unmount_all(struct fuzzer_state *state) {
  if (state->constant_state.diskless)
    return;

  CHECK_THAT(!state->constant_state.native_mode);
  TRACE(state, "Unmounting all...");

  res_close_all_fds(state);

  // perform umount()
  for (int part = 0; part < state->constant_state.part_count; ++part) {
    partition_t *partition = &state->partitions[part];
    if (strncmp(partition->fstype, FSTYPE_RAW, strlen(FSTYPE_RAW)) == 0) {
      continue;
    }
    int ret = lkl_umount_dev(partition->disk_id, 0, 0, 1);
    if (ret) {
      // TODO
      WARN(state, "Cannot unmount #%d, type = %s (%s), just exiting...",
           part, partition->fstype, lkl_strerror(ret));
      stop_processing(state);
    }
  }
}

static void mount_all(struct fuzzer_state *state)
{
  static bool first_time = true;
  if (state->constant_state.diskless)
    return;

  CHECK_THAT(!state->constant_state.native_mode);

  kernel_dump_all_pertitions_if_requested(state);

  TRACE(state, "Mounting all...");

  for (int part = 0; part < state->constant_state.part_count; ++part)
  {
    partition_t *partition = &state->partitions[part];
    if (strncmp(partition->fstype, FSTYPE_RAW, strlen(FSTYPE_RAW)) == 0) {
      continue;
    }
    int mount_flags = read_only ? MS_RDONLY : MS_MGC_VAL;
    const char *mount_options;

    if (strcmp(partition->fstype, "ext4") == 0)
      mount_options = "errors=remount-ro";
    else
      mount_options = mount_options_knob;

    int ret = lkl_mount_dev(
      partition->disk_id,
      0,
      partition->fstype,
      mount_flags,
      mount_options,
      partition->mount_point,
      MOUNT_POINT_LEN);

    if (ret) {
      WARN(state, "Cannot mount partition #%d, type = %s: %s",
           part, partition->fstype, lkl_strerror(ret));

      if (state->mutable_state.patch_was_invoked) {
        WARN(state, "Exiting cleanly because PATCH was invoked previously.");
        stop_processing(state);
      } else if (!first_time && (ret == -EPERM || ret == -EACCES)) {
        // Can occur due to dropped privileges
        WARN(state, "Permission denied on remount, exiting cleanly.");
        stop_processing(state);
      } else {
        abort();
      }
    }
    first_time = false;

    state->partitions[part].registered_fds[0] = -1; // -1 is an "invalid FD" for any partition
    state->partitions[part].registered_fds_count = 1;

    TRACE(state, "Successfully mounted partition #%d, type = %s",
          part, partition->fstype);
  }
}

static void patch_one(struct fuzzer_state *state, partition_t *partition)
{
  const unsigned param1 = res_get_u16(state) % partition->access_count;
  const int access_nr = ((partition->off_cur - (int)param1) % ACCESS_HISTORY_LEN + ACCESS_HISTORY_LEN) % ACCESS_HISTORY_LEN;

  const unsigned char op = res_get_u8(state);
  const int32_t arg = res_get_u32(state);
  const int patch_size = (op & 0x70) >> 4;
  const int patch_local_range = partition->off_end[access_nr] - partition->off_start[access_nr] - patch_size + 1;

  if (patch_local_range <= 0)
    return;

  const int32_t param2 = res_get_u32(state);
  const int patch_local_offset = (param2 > 0) ? (param2 % patch_local_range) : (param2 % patch_local_range + patch_local_range);
  size_t partition_offset = partition->off_start[access_nr] + patch_local_offset;
  void *patch_destination = partition->data + partition_offset;

  uint64_t original_data, patched_data;
  memcpy(&original_data, patch_destination, patch_size);
  patched_data = original_data;

  switch(op & 0x07) {
  case 0:
  case 1:
    patched_data += (int64_t)arg;
    break;
  case 2:
  case 3:
    patched_data = (int64_t)arg;
    break;
  case 4:
    patched_data &= arg;
    break;
  case 5:
    patched_data |= arg;
    break;
  case 6:
  case 7:
    patched_data ^= arg;
    break;
  }
  memcpy(patch_destination, &patched_data, patch_size);

  TRACE(state, "Patching at 0x%zx, size = %d: 0x%lx -> 0x%lx (op = 0x%02x, arg = 0x%x)",
        partition_offset, patch_size,
        original_data, patched_data,
        op & 0xff, arg);
}

static void my_printk(const char *msg, int len)
{
  static char print_buf[65536];

  if (!no_printk)
    fwrite(msg, len, 1, stderr);

  if (!boot_complete)
    return;

  if (patching_was_performed || no_bad_words == -1)
    return;

  memcpy(print_buf, msg, len);
  print_buf[len] = 0;

  if (exit_on_oom && (strstr(print_buf, "invoked oom-killer") ||
                      strstr(print_buf, "page allocation failure"))) {
    fprintf(stderr, "Exiting on OOM.\n");
    _exit(1);
  }

  if (strcasestr(print_buf, "errors=remount-ro"))
    return;

  for (unsigned i = 0; i < sizeof(BAD_WORDS) / sizeof(BAD_WORDS[0]); ++i) {
    if ((no_bad_words & (1 << i)) == 0 && strcasestr(print_buf, BAD_WORDS[i]))
      abort();
  }
}

// path is relative to current mount point (cwd for the time of scanning)!
static char file_scanner_tmp_buf[MAX_FILE_NAME_LEN];
// stack of visited inodes, to handle hard linked directory loops
static ino64_t inode_stack[128];
static int inode_stack_size;

static void recurse_into_directory(struct fuzzer_state *state, int part, struct lkl_dir *dir)
{
  struct lkl_linux_dirent64 *dirent;
  size_t old_len = strlen(file_scanner_tmp_buf); // might be optimized, but not on hot path anyway
  while ((dirent = lkl_readdir(dir)) != NULL) {
    // is this "." or ".."?
    if (strcmp(dirent->d_name, ".") == 0 || strcmp(dirent->d_name, "..") == 0) {
      continue;
    }

    // are we on a directory loop?
    int dir_loop = 0;
    for (int i = 0; i < inode_stack_size; ++i) {
      if (inode_stack[i] == dirent->d_ino) {
        dir_loop = 1;
        break;
      }
    }
    if (dir_loop) {
      continue;
    }

    // temporarily adding new path component
    snprintf(file_scanner_tmp_buf + old_len, sizeof(file_scanner_tmp_buf) - old_len, "/%s", dirent->d_name);
    state->mutable_state.file_names[state->current_state.file_name_count++] = strdup(file_scanner_tmp_buf);
    inode_stack[inode_stack_size++] = dirent->d_ino;

    // is this a directory itself?
    int stat_err;
#if LKL_HAS_STATX_SYSCALL
    struct lkl_statx statxbuf = {};
    stat_err = INVOKE_SYSCALL(state, statx, AT_FDCWD, (long)file_scanner_tmp_buf, 0, STATX_MODE, (long)&statxbuf);
    unsigned st_mode = statxbuf.stx_mode;
#else
    struct lkl_stat statbuf;
    stat_err = lkl_sys_stat(file_scanner_tmp_buf, &statbuf);
    unsigned st_mode = statbuf.st_mode;
#endif
    if (stat_err != 0) {
      TRACE(state, "stat: %s: %s", file_scanner_tmp_buf, STRERROR(state, stat_err));
      continue;
    }
    if (S_ISDIR(st_mode)) {
      int err;
      struct lkl_dir *dir_to_recurse = lkl_opendir(file_scanner_tmp_buf, &err);
      CHECK_THAT(dir_to_recurse != NULL);
      recurse_into_directory(state, part, dir_to_recurse);
      CHECK_INVOKER_ERRNO(state, lkl_closedir(dir_to_recurse));
    }

    // dropping path component
    file_scanner_tmp_buf[old_len] = '\0';
    inode_stack_size--;
  }
}

#else // USE_LKL

void kernel_setup_disk(struct fuzzer_state *state, const char *filename, const char *fstype)
{
  warn_lkl_not_supported();
}

#endif // USE_LKL

void kernel_configure_diskless(struct fuzzer_state *state, const char *mpoint)
{
  state->constant_state.diskless = true;
  state->constant_state.part_count = 1;
  partition_t *root_pseudo_partition = &state->partitions[0];

  root_pseudo_partition->size = 0;
  root_pseudo_partition->data = NULL;
  strcpy(root_pseudo_partition->mount_point, mpoint);
  strncpy(root_pseudo_partition->fstype,  "<root pseudo partition>", sizeof(root_pseudo_partition->fstype));
  root_pseudo_partition->registered_fds[0] = -1; // invalid FD
  root_pseudo_partition->registered_fds_count = 1; // count is never zero to avoid [x % 0]
}

void kernel_perform_remount(struct fuzzer_state *state)
{
  if (state->constant_state.native_mode) {
    WARN(state, "REMOUNT requested in native mode, exiting.");
    stop_processing(state);
  }
#ifdef USE_LKL
  unmount_all(state);
  mount_all(state);
#endif
}

void kernel_perform_patching(struct fuzzer_state *state)
{
  if (state->constant_state.native_mode) {
    WARN(state, "PATCH requested in native mode, exiting.");
    stop_processing(state);
  }
  if (state->constant_state.part_count > 1) {
    WARN(state, "PATCH requested in comparison mode, exiting.");
    stop_processing(state);
  }
  if (no_patch) {
    WARN(state, "PATCH requested, but is explicitly disabled, exiting.");
    stop_processing(state);
  }

#ifdef USE_LKL
  // Now, we have exactly one real partition
  partition_t *partition = &state->partitions[0];

  if (partition->access_count == 0)
    return;

  const int count = res_get_u8(state) % 32;
  TRACE(state, "PATCH count requested = %d", count);
  unmount_all(state);
  state->mutable_state.patch_was_invoked = true;
  patching_was_performed = true;
  for(int i = 0; i < count; ++i) {
    patch_one(state, partition);
  }
  mount_all(state);
#endif
}

void kernel_boot(struct fuzzer_state *state, const char *cmdline)
{
  if (state->constant_state.native_mode) {
    LOG_FATAL("Refusing to boot LKL in native mode!");
    abort();
  }
#ifdef USE_LKL
  add_all_disks(state);
  lkl_host_ops.print = my_printk;
  lkl_host_ops.panic = abort;
  lkl_start_kernel(&lkl_host_ops, cmdline);
  lkl_mount_fs("sysfs");
  lkl_mount_fs("proc");
  mount_all(state);
  boot_complete = true;
#endif
}

size_t kernel_read_from_file(struct fuzzer_state *state, const char *filename, const void *data, size_t size)
{
  int fd = INVOKE_SYSCALL(state, openat, AT_FDCWD, (long)filename, O_RDONLY, 0);
  CHECK_THAT(fd >= 0);
  ssize_t res = INVOKE_SYSCALL(state, read, fd, (long)data, (long)size);
  CHECK_THAT(res >= 0);
  INVOKE_SYSCALL(state, close, fd);
  return (size_t) res;
}

void kernel_dump_file_contents(struct fuzzer_state *state, const char *filename)
{
  static char contents[64 * 1024];
  size_t length = kernel_read_from_file(state, filename, contents, sizeof(contents) - 1);
  contents[length] = '\0';
  TRACE(state, "=== Contents of %s ===\n%s", filename, contents);
}

void kernel_write_to_file(struct fuzzer_state *state, const char *filename, const void *data, size_t size, int write_may_fail)
{
  TRACE_NO_NL(state, "Writing [%s] to %s... ", data, filename);
  int len = strlen(data);
  int fd = INVOKE_SYSCALL(state, openat, AT_FDCWD, (long)filename, O_WRONLY, 0);
  CHECK_THAT(fd >= 0);
  CHECK_THAT(INVOKE_SYSCALL(state, write, fd, (long)data, len) == len || write_may_fail);
  INVOKE_SYSCALL(state, close, fd);
  TRACE(state, "OK");
}

void kernel_write_string_to_file(struct fuzzer_state *state, const char *filename, const char *str, int write_may_fail)
{
  kernel_write_to_file(state, filename, str, strlen(str), write_may_fail);
}

void kernel_invoke_write_to_file(struct fuzzer_state *state)
{
#define OUTBUF_LEN 80
#define INBUF_LEN (OUTBUF_LEN * 4)
  const int file_index = res_get_u32(state) % state->current_state.file_name_count;
  const char * const file_name = state->mutable_state.file_names[file_index];
  static char path_name[1024];
  static char iobuf[INBUF_LEN + 1];
  static int break_indexes[INBUF_LEN + 2];
  int outlen;
  int fd;

  if (!strncmp(file_name, "./vm", 4) || !strcmp(file_name, "./kernel/threads-max")) {
    return;
  }
  sprintf(path_name, "%s/%s", state->partitions[0].mount_point, file_name);

  int selector = res_get_u8(state) & 3;
  int do_write_number = selector == 0;
  int do_write_word = selector == 1;

  TRACE(state, "Opening %s...", path_name);
  fd = INVOKE_SYSCALL(state, openat, AT_FDCWD, (long)path_name, do_write_word ? O_RDWR : O_WRONLY, 0);
  if (fd < 0) {
    WARN(state, "  Cannot open %s: %s", path_name, STRERROR(state, fd));
    return;
  } else {
    TRACE(state, "  FD = %d", fd);
  }

  if (do_write_number) {
    outlen = sprintf(iobuf, "%d", (int32_t)res_get_u32(state));
  } else if (do_write_word) {
    int inlen = INVOKE_SYSCALL(state, read, fd, (intptr_t)iobuf, INBUF_LEN);
    while (inlen > 0 && !isalnum(iobuf[inlen - 1])) {
      inlen -= 1;
    }
    iobuf[inlen] = '\0';
    TRACE(state, "  Read [%s].", iobuf);

    int break_count = 0;
    break_indexes[break_count++] = -1;
    for (int i = 0; i < inlen; ++i) {
      if (!isalnum(iobuf[i])) {
        break_indexes[break_count++] = i;
      }
    }
    break_indexes[break_count] = inlen;

    int word_index = res_get_u8(state) % break_count;
    outlen = break_indexes[word_index + 1] - (break_indexes[word_index] + 1);
    memmove(iobuf, iobuf + (break_indexes[word_index] + 1), outlen);
  } else {
    outlen = res_get_u8(state) % OUTBUF_LEN;
    res_copy_bytes(state, iobuf, outlen);
  }
  iobuf[outlen] = '\0';
  TRACE(state, "  Writing [%s]...", iobuf);

  INVOKE_SYSCALL(state, write, fd, (long)iobuf, outlen);
  INVOKE_SYSCALL(state, close, fd);
}

static void parse_device_id(const char *device_id_str, int *major, int *minor)
{
  const char *semicolon = strchr(device_id_str, ':');
  CHECK_THAT(semicolon != NULL);
  *major = atoi(device_id_str);
  *minor = atoi(semicolon + 1);
}

int kernel_open_device_by_sysfs_name(struct fuzzer_state *state, const char *name, const char *sysfs_id, int dev_kind)
{
  char sysfs_name[128];
  char dev_name[128];
  char device_id_str[32];
  int major, minor;

  if (is_native_invoker(state)) {
    sprintf(sysfs_name, "/sys/%s/dev", sysfs_id);
    sprintf(dev_name, "/tmp/%s", name);
  } else {
    sprintf(sysfs_name, "/sysfs/%s/dev", sysfs_id);
    sprintf(dev_name, "/%s", name);
  }

  TRACE(state, "Opening the device %s as %s...", sysfs_name, dev_name);

  // read device ID as string
  size_t sysfs_read_size = kernel_read_from_file(state, sysfs_name, device_id_str, sizeof(device_id_str) - 1);
  device_id_str[sysfs_read_size] = 0;
  TRACE(state, "  sysfs returned: %s", device_id_str);

  // parse string ID
  parse_device_id(device_id_str, &major, &minor);
  TRACE(state, "  parsed as: major = %d, minor = %d", major, minor);

  // crete device file
  dev_t dev = makedev(major, minor);
  int mknod_result = INVOKE_SYSCALL(state, mknodat, AT_FDCWD, (long)dev_name, dev_kind | S_IRUSR | S_IWUSR, dev);
  CHECK_INVOKER_ERRNO(state, mknod_result);
  TRACE(state, "  created device file: %s", dev_name);

  // open the just created device
  int fd = INVOKE_SYSCALL(state, openat, AT_FDCWD, (long)dev_name, O_RDWR);
  CHECK_THAT(fd >= 0);
  TRACE(state, "  opened as fd = %d", fd);
  TRACE(state, "  DONE");

  return fd;
}


int kernel_scan_for_files(struct fuzzer_state *state, int part)
{
  if (state->constant_state.native_mode) {
    WARN(state, "Scanning files in a native mode makes little sense and anyway seems like a bad idea, exiting.");
    exit(1);
  }

  const int old_file_count = state->current_state.file_name_count;

#ifdef USE_LKL

  CHECK_INVOKER_ERRNO(state, lkl_sys_chdir(state->partitions[part].mount_point));
  // now assuming we are in LKL mode
  int err;
  struct lkl_dir *fs_root_dir = lkl_opendir(".", &err);
  CHECK_THAT(fs_root_dir != NULL);
  file_scanner_tmp_buf[0] = '.';
  file_scanner_tmp_buf[1] = '\0';
  recurse_into_directory(state, part, fs_root_dir);
  CHECK_INVOKER_ERRNO(state, lkl_closedir(fs_root_dir));
  CHECK_INVOKER_ERRNO(state, lkl_sys_chdir("/"));

#endif

  return state->current_state.file_name_count - old_file_count;
}

void kernel_dump_file_names(struct fuzzer_state *state)
{
  for (int i = 0; i < state->current_state.file_name_count; ++i) {
    TRACE(state, "  %s", state->mutable_state.file_names[i]);
  }
}

#if USE_LKL
void kernel_mk_char_devices(struct fuzzer_state *state)
{
  int err;
  char tmp_buf[128];
  char tmp_path[128];

  struct lkl_dir *sysfs_dev_char_dir = lkl_opendir("/sysfs/dev/char", &err);
  CHECK_THAT(sysfs_dev_char_dir != NULL);

  CHECK_INVOKER_ERRNO(state, lkl_sys_mkdir("/dev/", S_IFDIR | S_IRWXU | S_IRWXG | S_IRWXO) == 0);

  struct lkl_linux_dirent64 *dirent;
  while ((dirent = lkl_readdir(sysfs_dev_char_dir)) != NULL) {
    if (dirent->d_name[0] == '.') {
      continue;
    }

    int major, minor;
    parse_device_id(dirent->d_name, &major, &minor);

    snprintf(tmp_path, sizeof(tmp_path), "/sysfs/dev/char/%s/uevent", dirent->d_name);
    size_t uevent_length = kernel_read_from_file(state, tmp_path, tmp_buf, sizeof(tmp_buf) - 1);
    tmp_buf[uevent_length] = '\0';

    const char *marker = "DEVNAME=";
    char *dev_name = strstr(tmp_buf, marker);
    CHECK_THAT(dev_name != NULL);
    dev_name += strlen(marker);
    char *nl = strchr(dev_name, '\n');
    if (nl) {
      *nl = '\0';
    }

    for (int i = 0; dev_name[i]; ++i) {
      if (dev_name[i] == '/') {
        dev_name[i] = '_';
      }
    }

    snprintf(tmp_path, sizeof(tmp_path), "/dev/%s_%d_%d", dev_name, major, minor);
    CHECK_INVOKER_ERRNO(state, lkl_sys_mknodat(AT_FDCWD, tmp_path, S_IFCHR | S_IRWXU | S_IRWXG | S_IRWXO, makedev(major, minor)));
  }
  lkl_closedir(sysfs_dev_char_dir);
}
#endif
