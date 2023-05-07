ConfigureNonInstrumentedDirectory()

add_library(afl-generic-mutator SHARED
  afl-generic-mutator.cpp
  helpers.cpp
  journal.cpp
  mutations.cpp
  ../common/hashing.c
  ../common/options.c
)

add_library(mutator-injector SHARED mutator-injector.c)
target_link_libraries(mutator-injector afl-generic-mutator)

function(TestMutatorInterface id)
  if (KBDYSCH_ASAN_ENABLED)
    # TODO Make libmutator-injector.so preloadable into testfuzz executable with ASan enabled.
    return ()
  endif()
  add_test(
    NAME "mutator-interface-${id}"
    COMMAND ${CMAKE_SOURCE_DIR}/utils/cmake/test-mutator-interface.sh "$<TARGET_FILE:mutator-injector>" "$<TARGET_FILE:testfuzz>" "${CMAKE_CURRENT_LIST_DIR}/tests/${id}"
  )
endfunction()

TestMutatorInterface(variables)
TestMutatorInterface(sections)
TestMutatorInterface(resources)
TestMutatorInterface(resource-renumber)
TestMutatorInterface(proposed-changes)
