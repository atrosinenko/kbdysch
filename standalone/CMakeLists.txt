ConfigureNonInstrumentedDirectory()

if(NOT KBDYSCH_ASAN_ENABLED)
    add_link_options(-static)
endif()

add_executable(bpf bpf.c)
add_executable(fuse-player fuse-player.c)
