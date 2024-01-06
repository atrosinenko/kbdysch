# Base routines that are useful in any context (both harnesses and mutator).
#
# Originally, `common` library contained anything used by multiple harnesses.
# No mutators existed at that time, so LKL was assumed to always be an option.
#
# Let's call the new library `base` to not confuse it with `common`.
# It is expected to contain anything that is useful in *any* context (harness,
# mutator, anything else added in the future), maybe except for `standalone`
# (just because these are mostly single-file sources, so no libraries expected
# except for system-provided ones).
#
# Dependencies: system libraries (only those expected to unconditionally exist
#               on any supported host system).

add_library(base STATIC
  hashing.c
)