#!/bin/sh

export CC=afl-clang-fast
# Clone the LKL version patched to use GNU Pth instead of Pthreads
git clone https://github.com/atrosinenko/lkl-linux.git --branch kbdysch --depth 10

# Apply some fuzzing-related patches
pushd lkl-linux
patch -p1 < ../lkl-kbdysch.patch
make -C tools/lkl -j8
popd

# Build the harnesses
mkdir build
pushd build
cp ../lkl-linux/tools/lkl/liblkl.a .
ln -s ../lkl-linux/tools/lkl/include/ lkl-include
cmake ../runtime
make
popd

