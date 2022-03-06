add_library(common_lib STATIC
  kernel.c
  logging.c
  packet-dumper.c
  resources.c
  util.c
)

if (USE_LKL)
    target_compile_definitions(common_lib PUBLIC -DUSE_LKL)
    target_link_libraries(common_lib lkl)
endif()

if (FAKE_TIME)
  add_library(fake_time OBJECT fake_time.c)
  set(OVERRIDE_LIBS "${OVERRIDE_LIBS};fake_time" PARENT_SCOPE)
endif()

target_link_libraries(common_lib -lpth -lrt -pthread)

add_library(invoker_lib STATIC
  invoker-helpers.c
)
target_link_libraries(invoker_lib common_lib)

find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP libpcap)
set(USE_LIBPCAP ${PCAP_FOUND} CACHE BOOL "Link to PCAP library")
if (USE_LIBPCAP)
    target_link_libraries(common_lib ${PCAP_LIBRARIES})
    target_include_directories(common_lib PRIVATE ${PCAP_INCLUDE_DIRS})
    target_compile_options(common_lib PRIVATE ${PCAP_CFLAGS_OTHER})
    target_compile_definitions(common_lib PRIVATE -DHAS_LIBPCAP)
endif()
