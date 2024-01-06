#include "kbdysch/userspace/dm.h"

#include "kbdysch/kbdysch.h"

#include <assert.h>
#include <fcntl.h>
#include <string.h>

#include <sys/ioctl.h>
#include <linux/dm-ioctl.h>

namespace kbdysch {

int dm_configurator::open_dm_control(struct fuzzer_state *state) {
  return kernel_open_device_by_sysfs_name(
      state, "dm-control", "class/misc/device-mapper", S_IFCHR);
}

dm_configurator::dm_configurator(ioctl_wrapper &ioctl,
                                 const std::string &device_name)
  : IoctlWrapper(ioctl), DeviceName(device_name) { }

uint8_t *dm_configurator::alloc_raw(unsigned alloc_size) {
  size_t old_size = ArgStorage.size();
  ArgStorage.resize(old_size + alloc_size);

  uint8_t *ptr = &ArgStorage[old_size];
  memset(ptr, 0, alloc_size);
  update_data_size();

  return ptr;
}

uint8_t *dm_configurator::get_raw_at(unsigned offset, unsigned size) {
  assert(offset < ArgStorage.size());
  assert(size <= ArgStorage.size());
  assert(offset + size <= ArgStorage.size());

  return &ArgStorage[offset];
}

void dm_configurator::reset_arg() {
  ArgStorage.clear();
}

void dm_configurator::put_header() {
  auto *header = alloc<struct dm_ioctl>();
  header->version[0] = 4;
  header->version[1] = 0;
  header->version[2] = 0;
  header->data_start = ArgStorage.size();
  assert(DeviceName.size() + 1 <= sizeof(header->name));
  strcpy(header->name, DeviceName.c_str());
}

void dm_configurator::put_table(unsigned sector_start,
                                unsigned num_sectors,
                                const std::string &type,
                                const std::string &args) {
  // Only a single table supported for now
  auto *header = get_at<struct dm_ioctl>(0);
  assert(header->target_count == 0);
  header->target_count = 1;

  auto *target = alloc<struct dm_target_spec>();
  target->sector_start = sector_start;
  target->length = num_sectors;
  assert(type.size() + 1 <= sizeof(target->target_type));
  strcpy(target->target_type, type.c_str());

  char *target_args = (char *)alloc_raw(args.size() + 1);
  strcpy(target_args, args.c_str());
}

void dm_configurator::update_data_size() {
  auto *header = get_at<struct dm_ioctl>(0);
  header->data_size = ArgStorage.size();
}

void dm_configurator::create_device() {
  reset_arg();
  put_header();
  IoctlWrapper.invoke(DM_DEV_CREATE, ArgStorage.data());
}

void dm_configurator::load_table(unsigned sector_start,
                                 unsigned num_sectors,
                                 const std::string &type,
                                 const std::string &args) {
  reset_arg();
  put_header();
  put_table(sector_start, num_sectors, type, args);
  IoctlWrapper.invoke(DM_TABLE_LOAD, ArgStorage.data());
}

void dm_configurator::suspend() {
  reset_arg();
  put_header();
  IoctlWrapper.invoke(DM_DEV_SUSPEND, ArgStorage.data());
}

} // namespace kbdysch

