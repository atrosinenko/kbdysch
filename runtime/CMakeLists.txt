cmake_minimum_required(VERSION 3.0)
project(kbdysch)

option(USE_LKL          "Link with LKL (otherwise just build invokers for the host kernel)" ON)
option(USE_INVOKERS     "Build fuzzers that require invokers to be generated first" ON)
set(   LKL_INCLUDE_PATH "${PROJECT_BINARY_DIR}/lkl-include" CACHE STRING "Full path to the tools/lkl/include of LKL build")
set(   LKL_LIB_PATH     "${PROJECT_BINARY_DIR}/liblkl.so"   CACHE STRING "Full path to LKL library file")

if (USE_LKL)
    link_libraries(${LKL_LIB_PATH})
    include_directories(${LKL_INCLUDE_PATH})
    add_definitions(-DUSE_LKL)
endif()

add_subdirectory(common)
include(common/Helpers.cmake)

RegisterInvoker(fs)
RegisterHarnessWithInvoker(fsfuzz fs)
RegisterHarness(bpffuzz)
RegisterHarness(hidfuzz)
RegisterHarness(partfuzz)
