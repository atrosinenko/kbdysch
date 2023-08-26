#include "kbdysch/block.h"
#include "kbdysch/input.h"
#include "kbdysch/invoker-utils.h"
#include "kbdysch/kbdysch.h"
#include "kbdysch/mutator-interface.h"
#include "kbdysch/options.h"
#include "kbdysch/userspace/dm.h"
#include "kbdysch/userspace/files.h"
#include "kbdysch/userspace/ioctl-wrapper.h"

#include <assert.h>
#include <fcntl.h>

#include <string>

using namespace kbdysch;

static const unsigned MAX_OPS = 1024;
const size_t SCRATCH_SIZE = 4 * 1024;

namespace kbdysch {

class blockdev_under_test {
public:
  blockdev_under_test(fuzzer_state *state)
      : State(state) {}

  virtual void init_before_boot() = 0;
  virtual void init_after_boot() = 0;

  void read(size_t offset, uint8_t *data, size_t size);
  void write(size_t offset, uint8_t *data, size_t size);

  /// Performs device-specific actions that should not be observable via
  /// generic block device I/O.
  virtual void do_maintainance() {
    // nothing by default
  }

  size_t get_size() const { return NumBytes; }

  virtual ~blockdev_under_test() {}

protected:
  fuzzer_state *State;

  /// Observable size in bytes
  size_t NumBytes;

  /// File descriptor corresponding to a _regular block device_ interface
  /// which implementation is being tested.
  int PublicFD = -1;

  void ensure_in_bounds(size_t offset, size_t access_size) {
    CHECK_THAT(offset < NumBytes);
    CHECK_THAT(access_size < NumBytes);
    CHECK_THAT(offset + access_size <= NumBytes);
  }

  std::string device_file_name(unsigned index, const std::string &fstype);
};

void blockdev_under_test::read(size_t offset, uint8_t *data, size_t size) {
  ensure_in_bounds(offset, size);
  long result = INVOKE_SYSCALL(State, pread64, PublicFD,
                               (intptr_t)data, (long)size, (long)offset);
  CHECK_THAT(result == size);
}

void blockdev_under_test::write(size_t offset, uint8_t *data, size_t size) {
  ensure_in_bounds(offset, size);
  long result = INVOKE_SYSCALL(State, pwrite64, PublicFD,
                               (intptr_t)data, (long)size, (long)offset);
  CHECK_THAT(result == size);
}

std::string blockdev_under_test::device_file_name(
    unsigned index, const std::string &fstype) {
  return "/block-" + std::to_string(index) + "-" + fstype;
}

class plain_blockdev : public blockdev_under_test {
public:
  plain_blockdev(fuzzer_state *state, unsigned num_bytes)
      : blockdev_under_test(state) {
    NumBytes = num_bytes;
  }

  void init_before_boot() override {
    BlockDeviceIndex = kernel_setup_raw_disk(State, "raw:plain", NumBytes);
  }

  void init_after_boot() override {
    auto name = device_file_name(BlockDeviceIndex, "raw:plain");
    PublicFD = CHECKED_SYSCALL(State, openat,
                               AT_FDCWD, (long)name.c_str(), O_RDWR);
  }

private:
  unsigned BlockDeviceIndex;
};

class dm_cache_blockdev : public blockdev_under_test {
public:
  dm_cache_blockdev(fuzzer_state *state, std::string meta_img,
                    std::string cache_img, std::string hdd_img)
      : blockdev_under_test(state), MetaImageFileName(meta_img),
        CacheImageFileName(cache_img), HddImageFileName(hdd_img) {}

  void init_before_boot() override {
    MetaIndex = kernel_setup_disk(
        State, MetaImageFileName.c_str(), "raw:meta");
    CacheIndex = kernel_setup_disk(
        State, CacheImageFileName.c_str(), "raw:cache");
    HddIndex = kernel_setup_disk(
        State, HddImageFileName.c_str(), "raw:hdd");
    NumBytes = get_file_size(HddImageFileName.c_str());
  }

  void init_after_boot() override {
    int fd_control = dm_configurator::open_dm_control(State);
    ioctl_wrapper ioctl(State, fd_control);

    dm_configurator configurator(ioctl, "test-cache");
    configurator.create_device();
    auto cache_args = device_file_name(MetaIndex, "raw:meta") + " " +
                      device_file_name(CacheIndex, "raw:cache") + " " +
                      device_file_name(HddIndex, "raw:hdd") + " " +
                      "64 1 writethrough default 0";
    configurator.load_table(0, NumBytes / SECTOR_SIZE, "cache", cache_args);
    configurator.suspend();

    PublicFD = kernel_open_device_by_sysfs_name(
        State, "dm-cache", "devices/virtual/block/dm-0", S_IFBLK);
  }

private:
  const size_t SECTOR_SIZE = 512;

  std::string MetaImageFileName;
  std::string CacheImageFileName;
  std::string HddImageFileName;

  unsigned MetaIndex;
  unsigned CacheIndex;
  unsigned HddIndex;
};

blockdev_under_test *create_dut(struct fuzzer_state *state, const char *argv[]) {
  const char *configuration_type = argv[0];
  if (!strcmp(configuration_type, "dm-cache")) {
    CHECK_THAT(argv[4] == NULL);
    return new dm_cache_blockdev(state, argv[1], argv[2], argv[3]);
  } else {
    LOG_FATAL("Unknown configuration type: %s", configuration_type);
    abort();
  }
}

} // namespace kbdysch

int main(int argc, const char *argv[]) {
  struct fuzzer_state *state = create_state(argc, argv, NULL);
  mutator_init();
  show_help_and_exit_if_needed(
      argc, argv,
      USAGE_WITH_ARGS("<kernel command line> dm-cache <cache.img> <meta.img> <hdd.img>")
      USAGE_THEN_DO  ("Run dm-cache test on Linux Kernel Library"));

  if (is_native_invoker(state)) {
    fprintf(stderr, "Native mode is not yet supported.\n");
    exit(1);
  }

  blockdev_under_test *dut = create_dut(state, &argv[2]);
  dut->init_before_boot();
  size_t num_bytes = dut->get_size();
  TRACE(state, "Image size: %u kB", num_bytes / 1024);

  blockdev_under_test *reference = new plain_blockdev(state, num_bytes);
  reference->init_before_boot();

  kernel_boot(state, argv[1]);

  dut->init_after_boot();
  reference->init_after_boot();

  uint8_t *scratch  = (uint8_t *)map_host_huge_pages_if_possible(state, "scratch",  -1, SCRATCH_SIZE);
  uint8_t *scratch2 = (uint8_t *)map_host_huge_pages_if_possible(state, "scratch2", -1, SCRATCH_SIZE);

  auto fill_with_pattern = [](uint8_t *ptr, size_t size, uint8_t fill_byte) {
    assert(size % BLK_SECTOR_SIZE == 0);
    for (size_t offset = 0; offset < size; offset += BLK_SECTOR_SIZE) {
      kbdysch_fill_pattern(&ptr[offset], fill_byte);
      fill_byte = fill_byte * 17u + 3u;
    }
  };

  for (size_t offset = 0; offset < num_bytes; offset += SCRATCH_SIZE) {
    size_t size = std::min(SCRATCH_SIZE, num_bytes - offset);
    dut->read(offset, scratch, size);
    reference->write(offset, scratch, size);
  }

  CHECKED_SYSCALL_0(state, sync);
  res_load_whole_stdin(state);

  input_wrapper input(state);

  if (setjmp(*res_get_stopper_env(state)) == 0) {
    for (int block_index = 0; block_index < MAX_OPS; ++block_index) {
      res_mark_section_start(state);
      size_t old_offset = res_get_cur_offset(state);

      unsigned start = input.u32() % num_bytes;
      input.reserve_bytes(4);
      unsigned length = input.next_bits<24>() % num_bytes;
      bool should_align = input.next_bits<4>() != 0;
      unsigned opcode = input.next_bits<4>();
      length = std::min(length % SCRATCH_SIZE, num_bytes - start);

      if (should_align) {
        start &= ~511LU;
        length &= ~511LU;
      }

      TRACE(state, "start = 0x%x length = 0x%x opcode = %x",
            start, length, opcode);

      switch (opcode & 0x03) {
      case 0x00: {
        uint8_t fill = block_index;
        unsigned offset = (512LU - start) & 511LU;

        memset(scratch, fill, offset);
        fill_with_pattern(&scratch[offset], std::max(0, (int)length - (int)offset) & ~511LU, fill);
        // TODO fill the remainder

        dut->write(start, scratch, length);
        reference->write(start, scratch, length);
        break;
      }
      case 0x01:
        memset(scratch, -1, length);
        memset(scratch2, 1, length);
        dut->read(start, scratch, length);
        reference->read(start, scratch2, length);
        if (memcmp(scratch, scratch2, length)) {
          LOG_FATAL("Read at offset 0x%zx, length 0x%zx: contents differ",
                    start, length);
          abort();
        }
        break;
      case 0x02:
        dut->do_maintainance();
        break;
      case 0x03:
        INVOKE_SYSCALL_0(state, sync);
        break;
      }

      size_t decoded_bytes = res_get_cur_offset(state) - old_offset;
      align_next_block(state, block_index, decoded_bytes);
    }
  }
  print_summary_at_exit(state);
  return 0;
}
