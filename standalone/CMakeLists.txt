set(KBDYSCH_STANDALONE_C_COMPILER "cc" CACHE STRING "C compiler for non-instrumented standalone executables")

set(CMAKE_C_COMPILER ${KBDYSCH_STANDALONE_C_COMPILER})

add_executable(bpf bpf.c)
add_executable(fuse-player fuse-player.c)
