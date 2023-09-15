# Helpers for interfacing with the kernel under test - either LKL
# or the host Linux kernel

include(CheckIncludeFile)

add_library(userspace_lib STATIC
  dm.cpp
  dummy-impls.cpp
  ioctl-wrapper.cpp
)
# TODO Fix circular dependencies between userspace_lib and common_lib
target_link_libraries(userspace_lib common_lib)

check_include_file(linux/btrfs.h HAS_LINUX_BTRFS_H)
if (HAS_LINUX_BTRFS_H)
    target_compile_definitions(userspace_lib PUBLIC HAS_LINUX_BTRFS_H)
    target_sources(userspace_lib PRIVATE btrfs.cpp)
endif()
