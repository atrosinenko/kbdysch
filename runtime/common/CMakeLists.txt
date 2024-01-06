set(COMMON_LIB_SOURCES
  block.c
  hugepages.c
  input.c
  invoker-helpers.c
  kernel.c
  logging.c
  mutator-interface.c
  packet-dumper.c
  resources.c
  util.c
)

add_library(common_lib STATIC ${COMMON_LIB_SOURCES})
target_link_libraries(common_lib base)
if (USE_LKL)
    target_compile_definitions(common_lib PUBLIC -DUSE_LKL)
    target_link_libraries(common_lib lkl)

    add_library(common_no_lkl STATIC ${COMMON_LIB_SOURCES})
    target_link_libraries(common_no_lkl base)
else()
    add_library(common_no_lkl ALIAS common_lib)
endif()

set(LKL_INHIBIT_LINK_TIME_ASSERTIONS OFF CACHE BOOL "Inhibit link-time assertions in LKL")
if (LKL_INHIBIT_LINK_TIME_ASSERTIONS)
  target_compile_definitions(common_lib PRIVATE LKL_INHIBIT_LINK_TIME_ASSERTIONS)
endif()

add_executable(kbdysch-hash kbdysch-hash.c)
target_link_libraries(kbdysch-hash base)

if (FAKE_TIME)
  add_library(fake_time OBJECT fake_time.c)
endif()

target_link_libraries(common_lib -lpth -lrt -pthread)

find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP libpcap)
set(USE_LIBPCAP ${PCAP_FOUND} CACHE BOOL "Link to PCAP library")
if (USE_LIBPCAP)
    target_link_libraries(common_lib ${PCAP_LIBRARIES})
    target_include_directories(common_lib PRIVATE ${PCAP_INCLUDE_DIRS})
    target_compile_options(common_lib PRIVATE ${PCAP_CFLAGS_OTHER})
    target_compile_definitions(common_lib PRIVATE -DHAS_LIBPCAP)
endif()
