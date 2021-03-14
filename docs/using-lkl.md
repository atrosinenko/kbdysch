Almost any usage of kBdysch involves linking it with [Linux Kernel Library](https://github.com/lkl/linux).
Just like the vanilla Linux kernel, LKL can be configured in many ways using
a standard Kconfig machinery. On the other hand, LKL is compiled in a slightly
nonstandard way by passing `-C tools/lkl` to `make`.

Here are some (possibly suboptimal) recipes.

## Compile LKL with the default config and AFL++ instrumentation

    make LLVM=1 LLVM_IAS=1 CC=/path/to/AFLplusplus/afl-clang-fast ARCH=lkl -C tools/lkl

Other useful arguments:
* `KCFLAGS="-mcpu=native"` - use all the available CPU extensions.
  The produced binaries may crash if executed on a significantly different CPU.
  This should not be a problem here, since the final result of fuzzing
  is usually a reproducer and not an executable code itself
* `-jN` (such as `-j4`) - as usual, compilation is much faster when performed
  in parallel

This command uses the default `arch/lkl/configs/defconfig` configuration.

## Clean the build tree

    make LLVM=1 LLVM_IAS=1 CC=/path/to/AFLplusplus/afl-clang-fast ARCH=lkl mrproper

Please note `mrproper` is executed from the top of the tree (i.e. without
`-C tools/lkl`).

## Rebuild incrementally after changing some kernel source

    make LLVM=1 LLVM_IAS=1 CC=/path/to/AFLplusplus/afl-clang-fast ARCH=lkl -C tools/lkl clean
    make LLVM=1 LLVM_IAS=1 CC=/path/to/AFLplusplus/afl-clang-fast ARCH=lkl -C tools/lkl

The first command cleans the `tools/lkl` directory **only**, so when it is built
again, the artifacts of the kernel build have to be reinstalled to `tools/lkl`
triggering an incremental rebuild.

## Changing the kernel config

    # Optionally, clean the entire tree
    make LLVM=1 LLVM_IAS=1 CC=/path/to/AFLplusplus/afl-clang-fast ARCH=lkl mrproper
    # Load the default config
    make LLVM=1 LLVM_IAS=1 CC=/path/to/AFLplusplus/afl-clang-fast ARCH=lkl defconfig
    # Edit the configuration
    make LLVM=1 LLVM_IAS=1 CC=/path/to/AFLplusplus/afl-clang-fast ARCH=lkl menuconfig
    # Make tools/lkl use it as the default
    cp .config arch/lkl/configs/defconfig

As usual, passing the correct `ARCH=...` argument (the same as will be used when
actually building, `lkl` in this case) is significant when operating on kernel
configs. Linux makefiles make use of "is CC a gcc or clang", so passing the
correct CC at configuration time is probably a good idea, too.
