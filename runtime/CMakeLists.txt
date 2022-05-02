option(USE_INVOKERS     "Build fuzzers that require invokers to be generated first" ON)
option(FAKE_TIME        "Report fake time values to Pth, LKL, etc. to increase the stability" ON)
option(USE_COMPACT_ENCODING "Read more compact descriptions when generating strings and buffer contents" ON)

include(common/Profile.cmake)
include(common/LKL.cmake)

set(GENERATED_INVOKER_DIR "${CMAKE_CURRENT_LIST_DIR}/generated")
include_directories(include)

if (USE_COMPACT_ENCODING)
    add_definitions(-DUSE_COMPACT_ENCODING)
endif()

add_compile_options(-fPIC)
include(common/Helpers.cmake)
add_subdirectory(dummy-lkl)
add_subdirectory(common)
add_subdirectory(mutators)

RegisterInvoker(fs)
RegisterHarnessWithInvoker(fsfuzz fs)
RegisterHarnessWithInvoker(fusefuzz fs)
RegisterHarness(bpffuzz)
TestHarnessWithArguments(bpffuzz mem=32M)
RegisterHarness(hidfuzz)
TestHarnessWithArguments(hidfuzz mem=32M)
RegisterHarness(partfuzz)
TestHarnessWithArguments(partfuzz mem=32M)
