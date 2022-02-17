#! /bin/bash

CFILE=$1

CLANG=clang-13
LLC=llc-13
CC=gcc

CFLAGS="-g -O2 -Wall"
LDFLAGS="-lbpf -lelf -lpthread"
NOSTDINC_FLAGS="-nostdinc -isystem $($CC -print-file-name=include)"
ARCH=$(uname -m | sed 's/x86_64/x86/' | sed 's/i386/x86/')
EXTRA_CFLAGS="-Werror"

LLFILE=${CFILE%%.*}.ll
OUTPUT=${CFILE%%.*}.o

# echo $CFILE

$CLANG -S $NOSTDINC_FLAGS $LINUXINCLUDE $EXTRA_CFLAGS \
	-D__KERNEL__ -D__ASM_SYSREG_H -D__BPF_TRACING__ \
	-DENABLE_ATOMICS_TESTS \
	-D__TARGET_ARCH_$ARCH \
	-Wno-unused-value -Wno-pointer-sign \
	-Wno-compare-distinct-pointer-types \
	-Wno-gnu-variable-sized-type-not-at-end \
	-Wno-tautological-compare \
	-Wno-unknown-warning-option \
	-Wno-address-of-packed-member \
	-O2 -g -emit-llvm -c $CFILE -o $LLFILE
$LLC -mcpu=v3 -march=bpf -filetype=obj -o $OUTPUT $LLFILE

# echo compiling $OUTPUT
