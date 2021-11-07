add_library(common_lib STATIC
  kernel.c
  logging.c
  resources.c
  util.c
)

if (FAKE_TIME)
  add_library(fake_time OBJECT fake_time.c)
  set(OVERRIDE_LIBS "${OVERRIDE_LIBS};fake_time" PARENT_SCOPE)
endif()

target_link_libraries(common_lib -lpth -lrt -pthread)

add_library(invoker_lib STATIC
  invoker-helpers.c
)
target_link_libraries(invoker_lib common_lib)
