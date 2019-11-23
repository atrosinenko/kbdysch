# kBdysch

kBdysch is a collection of fast Linux kernel specific fuzzing harnesses supposed to be run **in userspace** in a guided fuzzing manner.
It was designed with [AFL](https://github.com/google/AFL) compatibility in mind but AFL is not required to use this project.

## Fuzzing targets

_Currently_, kBdysch is capable of testing the following aspects of the kernel:
* file system implementations (for those residing on a single block device)
  * use one file system implementation as a model for testing some other one. _Just like proposed in AFL documentation but for the entire FS driver..._
* eBPF verifier
* HID subsystem via `uhid` emulated device

## Design

The main design ideas are:
* reuse [Linux Kernel Library](https://github.com/lkl/linux) project to run almost any part of the Linux kernel in user space just like a regular library
* reuse [Syzkaller](https://github.com/google/syzkaller) syscall descriptions for invoker generation
* use [GNU pth](https://www.gnu.org/software/pth/) library instead of classic Pthread so all the code is executed in a single OS thread
  * no need to worry about restoring existing threads after `fork()` being executed by a AFL's forkserver.
    This is especially useful since the kernel library may start in a matter of seconds, not microseconds, 
    and spawn some essential threads early in the boot sequence
  * bonus: you have much higher *stability* of behavior because now only discrete thread switch points are possible
    and no really concurrent memory accesses possible at all
* implement many different ways to detect abnormal behavior
  * crash, the classical one: if crashed **then failed**
  * _but now we have almost full control over the host-ops (block device operations, `printk`, etc.)! so, ..._
  * suspicious output: if printed some word (`error`, `corruption`, etc.) **then failed**
  * poisoned memory: if some output buffer returned by the kernel contains many _poisoned memory marker_
    bytes in a row **then failed** (existed in the original implementation but not yet moved to the refactored one)
  * `panic()`, `BUG()`, etc. triggered
  * misc minor sanity checking, such as "if negative syscall return value signifies error condition,
    then it should always return either non-negative value or a valid `errno` code"
  * _... and last, but in fact the original idea of this fuzzer..._
  * behavioral difference: this is strictly file system fuzzing related checker, but it can detect
    some subtle data corruptions by carefully separating operations on different file systems and comparing 
    the results of performing the same syscall sequence on them, considering every not-whitelisted discrepancy
    as a bug. This can find logical errors even when they do not manifest themselves as a bug on its own.
* since we proxy the block layer accesses to RAM-backed disk images anyway, we can record the accessed ranges
  to mutate it on image remount
  * doing this when the volume is mounted makes some sense but probably not too much, since it then simulates
    way too malicious (or just too buggy) block device and is not implemented for now
  * not compatible with many of the checkers listed above, especially the behavior difference

## Pre-existing works

kBdysch is not a unique approach. At least, there exist a [Janus fuzzer](https://github.com/sslab-gatech/janus) that uses both syscall invokers
and image mutators being applied to LKL. As far as I understand, their approach is slightly different:
* Janus tests one filesystem image at a time, while kBdysch can compare one implementation against another similar one
* test case shape:
  * Janus test case has a shape of `(Blob, Seq[Mutation], Seq[Syscall])` (apply some existing mutations
  to the FS image blob, invoke syscall sequence, then record new mutations naturally produced by the kernel)
  * kBdysch uses the shape of `(Blob, Seq[Either[Mutation, Syscall]])` (load some reference image,
  then in each forked child apply a sequence of operations to it **from clean state**, with one of operation being mutating
  touched parts)
* metadata handling:
  * Janus uses hand-written metadata parsers. This can handle checksum-protected metadata in an effective manner
  * kBdysch just records areas of image being accessed before remount (this can be handled trivially
    since we are already proxying block ops) to mutate them in the hope that they can be accessed again
    (at least with similar system calls) after remount . On one hand, this may be simply rejected by checksum-protected
    kernel metadata parsers. On the other hand, this allows much more trivial exploration of new file systems 
    (for those not requiring specific `mount` helpers, this may be achieved in a matter of minutes)

kBdysch is more tending to an approach of requiring as less manual work as possible while more relying on
similar to [Pulling JPEGs out of thin air](https://lcamtuf.blogspot.com/2014/11/pulling-jpegs-out-of-thin-air.html).

## Building from sources

To use the bundled invoker, just run the `build.sh` script.

In case you would want to modify the syscall descriptions, use `update_invokers.sh` script. You need Java installed in this case (and it will download all other Scala-related stuff on itself).

## Bugs

Technically, **this** fuzzer has not found anything yet at the time of writing this README, since it is
a partial rewrite of the original fuzzer that has found a couple tens of bugs but had quite awful code.
I tried to closely replicate its behavior, so it is expected to find roughly the same bugs as its predecessor.

On the bugs found by its predecessor, almost anything matched in `git log` with something like
`Reported-by:.*anatoly.trosinenko` is found via this approach (but some report can lead to 2-3 commits).

## Why such name?

This is not a random sequence of characters. 
And I don't try to fuzz this project users' ability to read English words, as well.
It is merely "K for Kernel" followed by a transliterated Russian word `БДЫЩ!` 
(an [onomatopoeia](https://en.wikipedia.org/wiki/Onomatopoeia) denoting the sound of some crash, similar to `BOOM!`).
Just like "borsch" but "bdysch".
