# Auxiliary executables linked to the same libraries as harnesses, etc.
# (as opposed to `standalone` directory that contains mostly self-contained
# programs to be sent as part of a reproducer, for example).

add_executable(kbdysch-hash kbdysch-hash.c)
target_link_libraries(kbdysch-hash base)

# FIXME Drop after upgrading to CMake 3.17+, see CMAKE_CURRENT_FUNCTION_LIST_DIR.
set(KBDYSCH_RUNTIME_UTILS_DIR "${CMAKE_CURRENT_LIST_DIR}" CACHE INTERNAL "")

function(AddInvokerDebugger invoker_name)
  add_executable(debug-${invoker_name} "${KBDYSCH_RUNTIME_UTILS_DIR}/invoker-debugger.c")
  # TODO Fix circular dependencies between userspace_lib and common_lib
  target_link_libraries(debug-${invoker_name}
    common_lib
    userspace_lib
    invoker_${invoker_name}
  )
endfunction()
