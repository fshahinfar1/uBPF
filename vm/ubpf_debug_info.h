#ifndef UBPF_DEBUG_INFO_H
#define UBPF_DEBUG_INFO_H
#include <stdint.h>
#include <unistd.h>
#include "ubpf_int.h"
int remove_perf_map(void);
void report_perf_map(struct ubpf_vm *vm, uint32_t prog_index);
int gen_elf_file_for_jit_code(uint8_t *, size_t, uint32_t);
#endif
