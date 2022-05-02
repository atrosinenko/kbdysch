# A dummy implementation of Linux Kernel Library interface for testing

if (NOT USE_DUMMY_LKL)
    return()
endif()

add_library(lkl STATIC dummy-lkl.c)
target_include_directories(lkl PUBLIC ${CMAKE_CURRENT_LIST_DIR})
target_compile_definitions(lkl PUBLIC -DUSE_DUMMY_LKL)
