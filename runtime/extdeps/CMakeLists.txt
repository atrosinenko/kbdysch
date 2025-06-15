# Utility functions that depend on some specific non-system library.
#
# Dependencies: system libraries (only those expected to unconditionally exist
#               on any supported host system), plus a single non-system library.

# These libraries should be usable by non-instrumented code.
ConfigureNonInstrumentedDirectory()

add_subdirectory(pth)
