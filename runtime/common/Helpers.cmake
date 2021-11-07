# Register auto-generated invoker located in runtime/generated/invoker-<NAME>.c
function(RegisterInvoker name)
  if (USE_INVOKERS)
    add_library(invoker_${name} STATIC
      "${GENERATED_INVOKER_DIR}/invoker-${name}.c")
    target_link_libraries(invoker_${name} invoker_lib)
    # FIXME: Remove after fixing code generator
    target_compile_options(invoker_${name} PRIVATE
      -Wno-incompatible-pointer-types)

    add_executable(debug-${name} utils/invoker-debugger.c)
    target_link_libraries(debug-${name} invoker_lib invoker_${name})
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
