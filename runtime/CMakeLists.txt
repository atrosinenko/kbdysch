cmake_minimum_required(VERSION 3.0)
project(kbdysch)

option(USE_LKL          "Link with lkl (otherwise just build invokers for the host kernel)" ON)
option(USE_INVOKERS     "Build fuzzers that require invokers to be generated first" ON)
set(   LKL_INCLUDE_PATH "${PROJECT_BINARY_DIR}/lkl-include" CACHE STRING "Full path to the tools/lkl/include of LKL build")
set(   LKL_LIB_PATH     "${PROJECT_BINARY_DIR}/liblkl.a"    CACHE STRING "Full path to the liblkl.a file")

include_directories(${PROJECT_SOURCE_DIR})

link_libraries(-lpth -lrt)

set(COMMON_SRCS kernel.c resources.c util.c)

if (USE_LKL)
    link_libraries(${LKL_LIB_PATH})
    include_directories(${LKL_INCLUDE_PATH})
    add_definitions(-DUSE_LKL)
endif()

if (USE_INVOKERS)
    add_definitions(-DUSE_INVOKERS)
endif()

if (USE_INVOKERS)
    add_executable(fsfuzz  fsfuzz.c  generated/invoker-fs.c ${COMMON_SRCS})
endif()

add_executable(bpffuzz bpffuzz.c ${COMMON_SRCS})
add_executable(hidfuzz hidfuzz.c ${COMMON_SRCS})
