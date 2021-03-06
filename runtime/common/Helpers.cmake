# Register auto-generated invoker located in runtime/generated/invoker-<NAME>.c
function(RegisterInvoker name)
  if (USE_INVOKERS)
    add_library("invoker_${name}" STATIC
      "${PROJECT_SOURCE_DIR}/generated/invoker-${name}.c")
    target_include_directories("invoker_${name}" PRIVATE
      "${PROJECT_SOURCE_DIR}/common")
    # FIXME: Remove after fixing code generator
    target_compile_options("invoker_${name}" PRIVATE
      -Wno-incompatible-pointer-types)
  endif()
endfunction()

function(PostprocessHarness name)
  target_link_libraries(${name} ${OVERRIDE_LIBS})
endfunction()

# Register harness located in runtime/<NAME>.c
function(RegisterHarness name)
  add_executable(${name} "${name}.c")
  target_link_libraries(${name} common_lib)
  PostprocessHarness(${name})
endfunction()

# Register harness <NAME> that has to be linked with <INVOKER_NAME>
function(RegisterHarnessWithInvoker name invoker_name)
  if (USE_INVOKERS)
    add_executable(${name} "${name}.c")
    target_link_libraries(${name} invoker_lib "invoker_${invoker_name}")
    PostprocessHarness(${name})
  endif()
endfunction()
