set(COMMON_LIB_SOURCES
  kernel.c
  logging.c
  mutator-interface.c
  packet-dumper.c
  resources.c
  util.c
)

set(INVOKER_LIB_SOURCES
  invoker-helpers.c
)

add_library(common_lib STATIC ${COMMON_LIB_SOURCES})
if (USE_LKL)
    target_compile_definitions(common_lib PUBLIC -DUSE_LKL)
    target_link_libraries(common_lib lkl)

    add_library(common_no_lkl STATIC ${COMMON_LIB_SOURCES})
else()
    add_library(common_no_lkl ALIAS common_lib)
endif()

if (FAKE_TIME)
  add_library(fake_time OBJECT fake_time.c)
  set(OVERRIDE_LIBS "${OVERRIDE_LIBS};fake_time" PARENT_SCOPE)
endif()

target_link_libraries(common_lib -lpth -lrt -pthread)

add_library(invoker_lib    STATIC ${INVOKER_LIB_SOURCES})
add_library(invoker_no_lkl STATIC ${INVOKER_LIB_SOURCES})
target_link_libraries(invoker_lib    common_lib)
target_link_libraries(invoker_no_lkl common_no_lkl)

find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP libpcap)
set(USE_LIBPCAP ${PCAP_FOUND} CACHE BOOL "Link to PCAP library")
if (USE_LIBPCAP)
    target_link_libraries(common_lib ${PCAP_LIBRARIES})
    target_include_directories(common_lib PRIVATE ${PCAP_INCLUDE_DIRS})
    target_compile_options(common_lib PRIVATE ${PCAP_CFLAGS_OTHER})
    target_compile_definitions(common_lib PRIVATE -DHAS_LIBPCAP)
endif()
