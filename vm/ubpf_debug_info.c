/* vim: set et ts=4 sw=4: */
#include <stdio.h>
#include <elf.h>
#include "ubpf_debug_info.h"

#define _unused __attribute__((unused))

/* Create a file at /tmp/perf-<PID>.map defining a symbol for the JITed
 * function. It is useful when using perf
 * */
void report_perf_map(struct ubpf_vm *vm, uint32_t prog_index)
{
    int ret;
    int pid = getpid();
    char filename[64];
    ret = snprintf(filename, 63, "/tmp/perf-%d.map", pid);
    if (ret < 0 ) {
        return;
    }

    FILE *f = fopen(filename, "a");
    if (f == NULL)
        return;

    char line[128];
    uint32_t size;
    size = snprintf(line, 128, "%p %lx prog-%d\n", (void*)vm->jitted[prog_index],
            vm->jitted_size[prog_index], prog_index);
    if (size < 0)
        return;
    fwrite(line, sizeof(char), size, f);
    fclose(f);
}

/* remove the file crated at /tmp/perf-<PID>.map
 * */
int remove_perf_map(void)
{
    int ret;
    int pid = getpid();
    char filename[64];
    ret = snprintf(filename, 63, "/tmp/perf-%d.map", pid);
    if (ret < 0 ) {
        return -1;
    }
    remove(filename);
    return 0;
}

/* Create an ELF binary for the JITed code. It should enable the code
 * annotation when using perf.
 * */
int gen_elf_file_for_jit_code(_unused uint8_t *code, _unused size_t sz, uint32_t prog_index)
{
    return -1; /* Not implemented yet ! */
    int ret;
    int pid = getpid();
    char filename[64];
    ret = snprintf(filename, 63, "/tmp/prog-%d-%d", prog_index, pid);
    if (ret < 0) {
        return -1;
    }
    FILE *f = fopen(filename, "wb");
    if (f == NULL)
        return -1;
    /*
     * */
    /* const Elf64_Ehdr ehdr; */

    fclose(f);
    return 0;
}
