cmake_minimum_required(VERSION 3.10)
project(kbdysch)
include(CTest)

include(runtime/common/Helpers.cmake)

set(KBDYSCH_STANDALONE_C_COMPILER   "cc"  CACHE STRING "C compiler for non-instrumented standalone executables")
set(KBDYSCH_STANDALONE_CXX_COMPILER "c++" CACHE STRING "C++ compiler for non-instrumented standalone executables")
set(KBDYSCH_PERFORM_AFL_TESTS OFF CACHE BOOL "Perform tests that depend on AFL++")

CheckBooleanPreprocessorExpression(
    "__SANITIZE_ADDRESS__ || __has_feature(address_sanitizer)"
    KBDYSCH_ASAN_ENABLED)

function(ConfigureNonInstrumentedDirectory)
    set(CMAKE_C_COMPILER   ${KBDYSCH_STANDALONE_C_COMPILER}   PARENT_SCOPE)
    set(CMAKE_CXX_COMPILER ${KBDYSCH_STANDALONE_CXX_COMPILER} PARENT_SCOPE)
    set(FILTERED_OPTIONS
        -fprofile-instr-generate
        -fcoverage-mapping
        "-fprofile-instr-use=.*"
    )
    foreach (OPT ${FILTERED_OPTIONS})
        string(REGEX REPLACE "${OPT}" "" CMAKE_C_FLAGS   "${CMAKE_C_FLAGS}")
        string(REGEX REPLACE "${OPT}" "" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
    endforeach()
    set(CMAKE_C_FLAGS   "${CMAKE_C_FLAGS}"   PARENT_SCOPE)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}" PARENT_SCOPE)
endfunction()

add_subdirectory(runtime)
add_subdirectory(standalone)
