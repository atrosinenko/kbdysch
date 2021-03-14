**Q:** QtCreator imports my build successfully but shows almost all headers as
       absent.

**A:** This may be the case when the selected build directory uses a
       non-standard C compiler (such as `afl-clang-fast`). Just initialize a
       fresh build directory with some casual system-wide `gcc`/`clang` as CC,
       then re-import the project.

**Q:** A harness initializes LKL successfully, then fails to accept any input.

**A:** LKL can be configured roughly like the regular Linux kernel. This means,
       say, `bpffuzz` may initialize LKL successfully and then fail with
       `ENOSYS` from LKL because the `bpf()` syscall was disabled in LKL config.
       See [this document](using-lkl.md) for details.

**Q:** What _kernel command line_ should I specify as the first argument
       for most harnesses?

**A:** Basically, `mem=32M` (or 128M, or other value depending on the task)
       should be enough. If you would like to pass any additional arguments
       to the kernel, make sure all they belong to the same `argv[]` element.
       When running a harness from `bash`, this can be accomplished with
       something like `./fsfuzz "mem=32M other.arg=1" ext4 btrfs`
