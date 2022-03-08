# See utils/collect-coverage.sh
set(KBDYSCH_COLLECT_PROFILE OFF CACHE BOOL   "Collect profile information for PGO and coverage reports")
set(KBDYSCH_PROFDATA        ""  CACHE STRING "Use previously collected profile")

if (KBDYSCH_COLLECT_PROFILE)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fprofile-instr-generate -fcoverage-mapping")
endif()

if (KBDYSCH_PROFDATA)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fprofile-instr-use=\"${KBDYSCH_PROFDATA}\"")
endif()
