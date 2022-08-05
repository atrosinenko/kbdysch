ConfigureNonInstrumentedDirectory()

if(NOT KBDYSCH_ASAN_ENABLED)
    add_compile_options(-static)
endif()

add_executable(bpf bpf.c)
add_executable(fuse-player fuse-player.c)
