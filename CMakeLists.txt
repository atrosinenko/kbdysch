cmake_minimum_required(VERSION 3.10)
project(kbdysch)

set(KBDYSCH_STANDALONE_C_COMPILER "cc" CACHE STRING "C compiler for non-instrumented standalone executables")

function(ConfigureNonInstrumentedDirectory)
    set(CMAKE_C_COMPILER ${KBDYSCH_STANDALONE_C_COMPILER} PARENT_SCOPE)
endfunction()

add_subdirectory(runtime)
add_subdirectory(standalone)
