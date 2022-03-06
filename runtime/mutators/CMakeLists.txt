add_library(afl-fsfuzz-mutator SHARED afl-fsfuzz-mutator.c)
target_link_libraries(afl-fsfuzz-mutator invoker_no_lkl invoker_fs)
