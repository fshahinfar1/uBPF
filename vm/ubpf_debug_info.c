/* vim: set et ts=4 sw=4: */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <libelf.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
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
 * @returns A file descriptor
 * */
int gen_elf_file_for_jit_code(uint8_t *code, size_t sz, uint32_t prog_index)
{
/* Make sure pointer is not null */
#define C(x,y) { (x) = (y); \
    if ((x) == NULL) { \
        fprintf(stderr, "Failed at %s:%d\n", __FILE__, __LINE__); \
        return -1; \
    } \
}
    int ret;
    int pid = getpid();
    char filename[64];
    Elf *e;
    Elf64_Ehdr *ehdr;
    Elf64_Phdr *phdr;
    Elf64_Shdr *shdr;
    Elf_Scn *scn;
    Elf_Data *data;
    FILE *f;
    int fd;

    if ( elf_version ( EV_CURRENT ) == EV_NONE ) {
        fprintf(stderr, "Failed at checking the libelf version (missing libelf)\n");
        return -1;
    }

    ret = snprintf(filename, 63, "/tmp/prog-%d-%d", prog_index, pid);
    if (ret < 0) {
        fprintf(stderr, "Failed at formating the file name\n");
        return -1;
    }
    C(f, fopen(filename, "wb"))
    fd = fileno(f);
    C(e, elf_begin(fd , ELF_C_WRITE , NULL))
    C(ehdr, elf64_newehdr(e))
    ehdr->e_ident[EI_DATA] = ELFDATA2LSB;
    ehdr->e_machine = EM_X86_64;
    ehdr->e_type = ET_EXEC;
    /* Create a new program header. Find its section, and set the buffer
     * pointer to code buffer we have.
     * Then update its section header by setting its name offset in the string
     * table, ...
     * */
    C(phdr, elf64_newphdr(e,1))
    C(scn, elf_newscn(e))
    C(data, elf_newdata(scn))
    data -> d_align = 8;
    data -> d_off = 0;
    data -> d_buf = code ;
    data -> d_type = ELF_T_WORD ;
    data -> d_size = sz;
    data -> d_version = EV_CURRENT ;
    /* Find this sections section header */
    C(shdr, elf64_getshdr(scn))
    shdr->sh_name = 1;
    shdr->sh_type = SHT_PROGBITS;
    shdr->sh_flags = SHF_ALLOC | SHF_EXECINSTR;
    shdr->sh_entsize = 0;

    /* Create the string table */
    size_t strtblsize = 1 + 6 + 10;
    char *strtbl = malloc(strtblsize);
    strtbl[0] = '\0';
    memcpy(&strtbl[1], ".text\0", 6);
    memcpy(&strtbl[7], ".shstrtab\0", 10);

    C(scn, elf_newscn(e))
    C(data, elf_newdata(scn))
    data->d_align = 1;
    data->d_off = 0;
    data->d_buf = strtbl;
    data->d_size = strtblsize;
    data->d_type = ELF_T_BYTE;
    data->d_version = EV_CURRENT;
    C(shdr, elf64_getshdr(scn))
    shdr->sh_name = 7;
    shdr->sh_type = SHT_STRTAB;
    shdr->sh_flags = SHF_STRINGS | SHF_ALLOC;
    shdr->sh_entsize = 0;

    /* store the index of the shstrtab */
    ehdr->e_shstrndx = elf_ndxscn(scn);

    void *x;
    C(x, elf_update (e , ELF_C_NULL ) < 0 ? NULL: (void *)1)

    phdr -> p_type = PT_PHDR | PT_LOAD ;
    phdr -> p_offset = ehdr->e_phoff ;
    phdr -> p_filesz = elf64_fsize ( ELF_T_PHDR , 1 , EV_CURRENT );
    phdr -> p_flags = PF_R | PF_X;
    elf_flagphdr (e , ELF_C_SET , ELF_F_DIRTY );
    C(x,  elf_update (e , ELF_C_WRITE ) < 0 ? NULL : (void *)1)
    
    /* report the offset at which the code has been writen to the binary object.
     * It will be used to mmap the file.
     * */

#undef C
    elf_end(e);
    fflush(f);
    fclose(f);

    fd = open(filename, O_RDONLY);
    return fd;
}
