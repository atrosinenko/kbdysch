#!/bin/sh -e

objcopy -I binary -O elf64-little --rename-section .data=.text "$1" "$2"

# Set ELF Machine field (at offset 0x12) to EM_BPF (0xF7)
# https://stackoverflow.com/questions/4783657
# Please note the built-in printf may not support \xHH notation
env printf '\xF7' | dd of="$2" bs=1 count=1 seek=18 conv=notrunc
