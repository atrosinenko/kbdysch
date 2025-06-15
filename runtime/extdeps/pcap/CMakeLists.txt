add_library(extdep_pcap STATIC
  packet-dumper.c
)

find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP libpcap)
set(USE_LIBPCAP ${PCAP_FOUND} CACHE BOOL "Link to PCAP library")
if (USE_LIBPCAP)
    target_link_libraries(extdep_pcap ${PCAP_LIBRARIES})
    target_include_directories(extdep_pcap PRIVATE ${PCAP_INCLUDE_DIRS})
    target_compile_options(extdep_pcap PRIVATE ${PCAP_CFLAGS_OTHER})
    target_compile_definitions(extdep_pcap PRIVATE -DHAS_LIBPCAP)
endif()
