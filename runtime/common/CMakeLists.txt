set(COMMON_LIB_SOURCES
  block.c
  hugepages.c
  input.c
  invoker-helpers.c
  kernel.c
  logging.c
  mutator-interface.c
  resources.c
  util.c
)

add_library(common_lib STATIC ${COMMON_LIB_SOURCES})
target_link_libraries(common_lib
  base
  extdep_pth
)
if (USE_LKL)
    target_compile_definitions(common_lib PUBLIC -DUSE_LKL)
    target_link_libraries(common_lib lkl)
endif()

set(LKL_INHIBIT_LINK_TIME_ASSERTIONS OFF CACHE BOOL "Inhibit link-time assertions in LKL")
if (LKL_INHIBIT_LINK_TIME_ASSERTIONS)
  target_compile_definitions(common_lib PRIVATE LKL_INHIBIT_LINK_TIME_ASSERTIONS)
endif()

target_link_libraries(common_lib -lrt)
