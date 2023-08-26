#ifndef KBDYSCH_USERSPACE_DM_H
#define KBDYSCH_USERSPACE_DM_H

#include "kbdysch/userspace/ioctl-wrapper.h"

#include <stdint.h>

#include <string>
#include <vector>

struct fuzzer_state;

namespace kbdysch {

class dm_configurator {
public:
  dm_configurator(ioctl_wrapper &ioctl, const std::string &device_name);

  void create_device();
  void load_table(unsigned sector_start, unsigned num_sectors,
                  const std::string &type, const std::string &args);
  void suspend();

  static int open_dm_control(struct fuzzer_state *state);

private:
  void reset_arg();
  void put_header();
  void put_table(unsigned sector_start, unsigned num_sectors,
                 const std::string &type, const std::string &args);
  void update_data_size();

  // NB: Can invalidate old pointers
  uint8_t *alloc_raw(unsigned alloc_size);

  uint8_t *get_raw_at(unsigned offset, unsigned size);

  template<typename T>
  T *alloc() {
    return (T *)alloc_raw(sizeof(T));
  }

  template<typename T>
  T *get_at(unsigned offset) {
    return (T *)get_raw_at(offset, sizeof(T));
  }

  ioctl_wrapper &IoctlWrapper;
  std::string DeviceName;
  std::vector<uint8_t> ArgStorage;
};

} // namespace kbdysch

#endif // KBDYSCH_USERSPACE_DM_H
