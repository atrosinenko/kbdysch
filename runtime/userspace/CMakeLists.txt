# Helpers for interfacing with the kernel under test - either LKL
# or the host Linux kernel

add_library(userspace_lib STATIC
  dm.cpp
  ioctl-wrapper.cpp
)
target_link_libraries(userspace_lib common_lib)
