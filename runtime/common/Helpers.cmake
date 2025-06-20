include(CheckCSourceCompiles)

# Register auto-generated invoker located in runtime/generated/invoker-<NAME>.c
function(RegisterInvoker name)
  if (USE_INVOKERS)
    add_library(invoker_${name} STATIC
      "${GENERATED_INVOKER_DIR}/invoker-${name}.c")
    target_link_libraries(invoker_${name} common_lib)
    # FIXME: Remove after fixing code generator
    target_compile_options(invoker_${name} PRIVATE
      -Wno-incompatible-pointer-types)

    AddInvokerDebugger(${name})
  endif()
endfunction()

function(PostprocessHarness name)
  UseFakeTime(name)
endfunction()

function(FindSourceByBasename out basename)
  if (EXISTS "${CMAKE_CURRENT_LIST_DIR}/${basename}.c")
    set(${out} "${basename}.c" PARENT_SCOPE)
  elseif (EXISTS "${CMAKE_CURRENT_LIST_DIR}/${basename}.cpp")
    set(${out} "${basename}.cpp" PARENT_SCOPE)
  else()
    message(FATAL_ERROR "Cannot find C or C++ source for '${basename}'")
  endif()
endfunction()

# Register harness located in runtime/<NAME>.c
function(RegisterHarness name)
  FindSourceByBasename(source_file ${name})
  add_executable(${name} "${source_file}")
  target_link_libraries(${name} common_lib userspace_lib)
  PostprocessHarness(${name})
endfunction()

# Register harness <NAME> that has to be linked with <INVOKER_NAME>
function(RegisterHarnessWithInvoker name invoker_name)
  if (USE_INVOKERS)
    FindSourceByBasename(source_file ${name})
    add_executable(${name} "${source_file}")
    target_link_libraries(${name} common_lib userspace_lib "invoker_${invoker_name}")
    PostprocessHarness(${name})
  endif()
endfunction()

function(TestHarness name)
  cmake_parse_arguments(PARSE_ARGV 1 TestHarness "" "" "ARGS;FILES")
  if (TestHarness_UNPARSED_ARGUMENTS)
    message(FATAL_ERROR "Unknown arguments: ${TestHarness_UNPARSED_ARGUMENTS}")
  endif()
  string(REPLACE ";" " " files "${TestHarness_FILES}")
  add_test(
    NAME "run-${name}"
    COMMAND ${CMAKE_SOURCE_DIR}/utils/cmake/test-run.sh "${files}" $<TARGET_FILE:${name}> ${TestHarness_ARGS}
  )
  if (KBDYSCH_PERFORM_AFL_TESTS)
    add_test(
      NAME "stability-${name}"
      COMMAND ${CMAKE_SOURCE_DIR}/utils/cmake/test-map-stability.sh "${files}" $<TARGET_FILE:${name}> ${TestHarness_ARGS}
    )
  endif()
endfunction()

function(CheckBooleanPreprocessorExpression expression out_var)
    set(test_source "
#if !defined(__has_feature)
#define __has_feature(x) 0
#endif
#if !(${expression})
#error
#endif
")
    # Let's check everytime, in case CMAKE_C_FLAGS changed
    unset(${out_var} CACHE)
    # Preprocess only, do not complain on absent main()
    set(CMAKE_REQUIRED_FLAGS "-E")
    check_c_source_compiles(${test_source} ${out_var})
endfunction()
