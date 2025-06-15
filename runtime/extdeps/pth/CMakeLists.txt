add_library(extdep_pth STATIC
  extdep_pth.c
)

target_link_libraries(extdep_pth -lpth -pthread)
