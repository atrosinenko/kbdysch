option(USE_DUMMY_LKL "Use dummy Linux Kernel Library for testing" OFF)
option(USE_LKL "Use Linux Kernel Library (otherwise just build invokers for the host kernel)" ON)

# Build LKL together with kbdysch or ...
set(LKL_SOURCE_PATH  ""    CACHE STRING "Path to the sources of LKL")
set(LKL_MAKE_FLAGS   "-j8" CACHE STRING "Extra make flags for LKL")

# ... use an existing build
set(LKL_INCLUDE_PATH "" CACHE STRING "Full path to the tools/lkl/include of LKL build")
set(LKL_LIB_PATH     "" CACHE STRING "Full path to LKL library file")

if (USE_DUMMY_LKL)
    # Dummy LKL is set up by its CMakeLists.txt, just a trivial handling here.
    set(USE_LKL ON)
    return()
endif()

if (NOT USE_LKL)
    return()
endif()

if (LKL_INCLUDE_PATH OR LKL_LIB_PATH)
    message(VERBOSE "Using external build of Linux Kernel Library.")
    if (LKL_SOURCE_PATH)
        message(FATAL_ERROR "Cannot specify both LKL sources and an existing build at the same time.")
    endif()
    if (NOT (LKL_INCLUDE_PATH AND LKL_LIB_PATH))
        message(FATAL_ERROR "Both LKL_INCLUDE_PATH and LKL_LIB_PATH should be specified if using an existing build of LKL.")
    endif()
elseif(LKL_SOURCE_PATH)
    message(VERBOSE "Building Linux Kernel Library as part of kbdysch build.")
else()
    message(FATAL_ERROR "Neither LKL sources nor existing build is specified.")
endif()

add_library(lkl INTERFACE)

if (LKL_SOURCE_PATH)
    include(ExternalProject)
    set(LKL_PREFIX      "${CMAKE_BINARY_DIR}/lkl-external")
    set(LKL_BUILD       "${LKL_PREFIX}/build")
    set(LKL_COMMON_OPTS ARCH=lkl LLVM=1 LLVM_IAS=1)
    set(LKL_PATH_OPTS   -C "${LKL_SOURCE_PATH}" "O=${LKL_BUILD}")
    set(LKL_TOOLCHAIN   "CC=${CMAKE_C_COMPILER}" "AR=${CMAKE_AR}" "LD=${CMAKE_LINKER}")
    set(LKL_FLAGS       "KCFLAGS=${CMAKE_C_FLAGS}")
    string(REPLACE " " ";" LKL_MAKE_FLAGS ${LKL_MAKE_FLAGS}) # Prevent unintended quoting
    ExternalProject_Add(lkl_build
        SOURCE_DIR "${LKL_SOURCE_PATH}"

        PREFIX     "${LKL_PREFIX}"
        BINARY_DIR "${LKL_BUILD}"

        CONFIGURE_COMMAND ""
        BUILD_COMMAND     make ${LKL_COMMON_OPTS} ${LKL_PATH_OPTS} ${LKL_TOOLCHAIN} ${LKL_FLAGS} ${LKL_MAKE_FLAGS} -C tools/lkl clean all
        BUILD_BYPRODUCTS  "${LKL_BUILD}/tools/lkl/lib/liblkl.so"
        INSTALL_COMMAND   ""
        USES_TERMINAL_BUILD TRUE
    )
    target_link_libraries(lkl INTERFACE "${LKL_BUILD}/tools/lkl/lib/liblkl.so")
    target_include_directories(lkl INTERFACE "${LKL_BUILD}/tools/lkl/include" "${LKL_SOURCE_PATH}/tools/lkl/include")
    add_dependencies(lkl lkl_build)
else()
    target_link_libraries(lkl INTERFACE "${LKL_LIB_PATH}")
    target_include_directories(lkl INTERFACE "${LKL_INCLUDE_PATH}")
endif()
