add_library(common_lib STATIC
  api_defs.h
  common-defs.h
  compiler.h
  internal-defs.h
  invoker-utils.h
  kbdysch.h
  kernel.c
  resources.c
  util.c
)
target_include_directories(common_lib PUBLIC ${PROJECT_SOURCE_DIR}/common)
target_link_libraries(common_lib -lpth -lrt)

add_library(invoker_lib STATIC
  invoker-helpers.c
)
target_include_directories(invoker_lib PUBLIC ${PROJECT_SOURCE_DIR}/common)
target_link_libraries(invoker_lib common_lib)
