option(FAKE_TIME "Report fake time values to Pth, LKL, etc. to increase the stability" ON)

if (FAKE_TIME)
  add_library(fake_time OBJECT fake_time.c)
endif()

function(UseFakeTime target)
  if (FAKE_TIME)
    target_sources(${name} PUBLIC $<TARGET_OBJECTS:fake_time>)
    target_link_libraries(${name} -ldl)
  endif()
endfunction()
