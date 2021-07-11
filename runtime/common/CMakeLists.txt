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

if (FAKE_TIME)
  add_library(fake_time OBJECT fake_time.c)
  set(OVERRIDE_LIBS "${OVERRIDE_LIBS};fake_time" PARENT_SCOPE)
endif()

target_include_directories(common_lib PUBLIC ${PROJECT_SOURCE_DIR}/common)
target_link_libraries(common_lib -lpth -lrt)

add_library(invoker_lib STATIC
  invoker-helpers.c
)
target_include_directories(invoker_lib PUBLIC ${PROJECT_SOURCE_DIR}/common)
target_link_libraries(invoker_lib common_lib)
