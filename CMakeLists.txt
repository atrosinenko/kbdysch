cmake_minimum_required(VERSION 3.10)
project(kbdysch)
include(CTest)

set(KBDYSCH_STANDALONE_C_COMPILER "cc" CACHE STRING "C compiler for non-instrumented standalone executables")
set(KBDYSCH_PERFORM_AFL_TESTS OFF CACHE BOOL "Perform tests that depend on AFL++")

function(ConfigureNonInstrumentedDirectory)
    set(CMAKE_C_COMPILER ${KBDYSCH_STANDALONE_C_COMPILER} PARENT_SCOPE)
    set(FILTERED_OPTIONS
        -fprofile-instr-generate
        -fcoverage-mapping
        "-fprofile-instr-use=.*"
    )
    foreach (OPT ${FILTERED_OPTIONS})
        string(REGEX REPLACE "${OPT}" "" CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")
    endforeach()
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS}" PARENT_SCOPE)
endfunction()

add_subdirectory(runtime)
add_subdirectory(standalone)
