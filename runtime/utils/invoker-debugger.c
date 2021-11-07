#include "kbdysch.h"
#include "invoker-utils.h"

int main(int argc, const char *argv[]) {
  const char *args[] = {"", "native"};
  struct fuzzer_state *state = create_state(2, args, NULL);
  kernel_configure_diskless(state, argv[1] /* current directory */);
  const char **offset_strings = &argv[2];
  const int block_num = argc - 2;

  res_load_whole_stdin(state);

  if (setjmp(*res_get_stopper_env(state)) == 0) {
    for (int block_index = 0; block_index < block_num; ++block_index) {
      int offset = atoi(offset_strings[block_index]) - 1;
      skip_block_if_requested(state, block_index);
      res_rewind_input(state, offset);
      do_invoke(state, block_index);
    }
  }
}
