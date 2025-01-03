/*
 * Copyright 2015 Big Switch Networks, Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdarg.h>
#include <inttypes.h>
#include "ubpf_int.h"
#include <elf.h>

/* Include maps */
#include "maps/ubpf_bf.h"
#include "maps/ubpf_countmin.h"
#include "maps/ubpf_hashmap.h"
#include "maps/ubpf_array.h"

#define MAX_SECTIONS 32

#ifndef EM_BPF
#define EM_BPF 247
#endif

struct bounds {
    const void *base;
    uint64_t size;
};

struct section {
    const Elf64_Shdr *shdr;
    const void *data;
    uint64_t size;
};

typedef struct {
    uint32_t off;
    uint32_t size;
} prog_info_t;

static const void *
bounds_check(struct bounds *bounds, uint64_t offset, uint64_t size)
{
    if (offset + size > bounds->size || offset + size < offset) {
        return NULL;
    }
    return bounds->base + offset;
}

static int
initiate_map_obj(struct ubpf_map *map,  const struct ubpf_map_def *map_def,
        char **errmsg)
{
    map->type = map_def->type;
    map->key_size = map_def->key_size;
    map->value_size = map_def->value_size;
    map->max_entries = map_def->max_entries;

    switch(map_def->type) {
        case UBPF_MAP_TYPE_ARRAY:
            map->ops = ubpf_array_ops;
            map->data = ubpf_array_create(map_def);
            break;
        case UBPF_MAP_TYPE_BLOOMFILTER:
            map->ops = ubpf_bf_ops;
            map->data = ubpf_bf_create(map_def);
            break;
        case UBPF_MAP_TYPE_COUNTMIN:
            map->ops = ubpf_countmin_ops;
            map->data = ubpf_countmin_create(map_def);
            break;
        case UBPF_MAP_TYPE_HASHMAP:
            map->ops = ubpf_hashmap_ops;
            map->data = ubpf_hashmap_create(map_def);
            break;
        default:
            if (errmsg)
                *errmsg = ubpf_error("unrecognized map type: %d", map_def->type);
            return -1;
    }

    if (!map->data) {
        if (errmsg)
            *errmsg = ubpf_error("failed to allocate memory");
        return -1;
    }
    return 0;
}

/* this function finds functions defined in the first .text section of elf file
 * The function begining address of each function is set in the progs. It will
 * find upto max_progs number of functions.
 *
 * @param sections: parsed sections of the elf file
 * @param count_sections: number of sections
 * @param progs: an array of integers that will be set to the function offset
 * @param max_progs: size of the progs array
 * @returns number of functions found
 * */
static int _get_funcs(struct section *sections, size_t count_sections,
        prog_info_t *progs, size_t max_progs)
{
    int i;
    int text_shndx = 0;
    int symbol_count = 0;
    int str_tbl_shndx = -1;
    const Elf64_Sym *symbol_table = NULL;
    /* Find first text section */
    for (i = 0; i < count_sections; i++) {
        const Elf64_Shdr *shdr = sections[i].shdr;
        if (shdr->sh_type == SHT_PROGBITS &&
                shdr->sh_flags == (SHF_ALLOC|SHF_EXECINSTR)) {
            text_shndx = i;
            break;
        }
    }

    /* Find symbol table && string table*/
    for (i = 0; i < count_sections; i++) {
        const Elf64_Shdr *shdr = sections[i].shdr;
        if(shdr->sh_type == SHT_SYMTAB) {
            symbol_table = sections[i].data;
            symbol_count = sections[i].size / shdr->sh_entsize;
        }

        if (shdr->sh_type == SHT_STRTAB && str_tbl_shndx == -1) {
            str_tbl_shndx = i;
        }
    }
    if (symbol_count == 0 || symbol_table == NULL) {
        fprintf(stderr, "Did not found the symbol table!\n");
        return 0;
    }
    if (str_tbl_shndx == -1) {
        fprintf(stderr, "Did not found the string table\n");
        return 0;
    }

    printf("symbol count: %d\n", symbol_count);
    /* Go through symbols and find functions in the first .text section */
    const char *strtbl = sections[str_tbl_shndx].data;
    int strtbl_sz = sections[str_tbl_shndx].size;
    int counter = 0;
    for (i = 0; i < symbol_count; i++) {
        const Elf64_Sym * sym = &symbol_table[i];
        if (sym->st_shndx != text_shndx)
            continue;
        if (ELF64_ST_TYPE(sym->st_info) != STT_FUNC)
            continue;
        int name_index = sym->st_name;
        assert (name_index < strtbl_sz);
        const char *name = &strtbl[name_index];
        printf("[%d] Function: %s, Address: 0x%lx, Size: %ld\n",
                counter, name, sym->st_value, sym->st_size); 
        /* void *prog = sections[text_shndx].data + sym->st_value; */
        progs[counter].off = sym->st_value;
        progs[counter].size = sym->st_size;
        counter++;
        if (counter >= max_progs)
            break;
    }
    return counter;
}

int
ubpf_load_elf(struct ubpf_vm *vm, const void *elf, size_t elf_size, char **errmsg)
{
    struct bounds b = { .base=elf, .size=elf_size };
    void *text_copy = NULL;
    void *str_copy = NULL;
    struct ubpf_map *map = NULL;
    int i;

    const Elf64_Ehdr *ehdr = bounds_check(&b, 0, sizeof(*ehdr));
    if (!ehdr) {
        *errmsg = ubpf_error("not enough data for ELF header");
        goto error;
    }

    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG)) {
        *errmsg = ubpf_error("wrong magic");
        goto error;
    }

    if (ehdr->e_ident[EI_CLASS] != ELFCLASS64) {
        *errmsg = ubpf_error("wrong class");
        goto error;
    }

    if (ehdr->e_ident[EI_DATA] != ELFDATA2LSB) {
        *errmsg = ubpf_error("wrong byte order");
        goto error;
    }

    if (ehdr->e_ident[EI_VERSION] != 1) {
        *errmsg = ubpf_error("wrong version");
        goto error;
    }

    if (ehdr->e_ident[EI_OSABI] != ELFOSABI_NONE) {
        *errmsg = ubpf_error("wrong OS ABI");
        goto error;
    }

    if (ehdr->e_type != ET_REL) {
        *errmsg = ubpf_error("wrong type, expected relocatable");
        goto error;
    }

    if (ehdr->e_machine != EM_NONE && ehdr->e_machine != EM_BPF) {
        *errmsg = ubpf_error("wrong machine, expected none or BPF, got %d",
                             ehdr->e_machine);
        goto error;
    }

    if (ehdr->e_shnum > MAX_SECTIONS) {
        *errmsg = ubpf_error("too many sections");
        goto error;
    }

    /* Parse section headers into an array */
    struct section sections[MAX_SECTIONS];
    for (i = 0; i < ehdr->e_shnum; i++) {
        const Elf64_Shdr *shdr = bounds_check(&b, ehdr->e_shoff + i*ehdr->e_shentsize, sizeof(*shdr));
        if (!shdr) {
            *errmsg = ubpf_error("bad section header offset or size");
            goto error;
        }

        const void *data = bounds_check(&b, shdr->sh_offset, shdr->sh_size);
        if (!data) {
            *errmsg = ubpf_error("bad section offset or size");
            goto error;
        }

        sections[i].shdr = shdr;
        sections[i].data = data;
        sections[i].size = shdr->sh_size;
    }

    /* Get address of functions defined in the first .text section */
    prog_info_t progs[MAX_YIELD_CHAIN_FUNCS];
    int sz = _get_funcs(sections, ehdr->e_shnum, progs, MAX_YIELD_CHAIN_FUNCS);
    if (sz == 0) {
        ubpf_error("did not found any functions");
    }
    vm->sz_yield_chain = sz;
    vm->insts = calloc(sz, sizeof(void *));
    vm->num_insts = calloc(sz, sizeof(uint16_t));
    vm->jitted = calloc(sz, sizeof(ubpf_jit_fn));
    vm->jitted_size = calloc(sz, sizeof(size_t));
    assert (progs[0].off == 0);

    /* Find first text section */
    int text_shndx = 0;
    for (i = 0; i < ehdr->e_shnum; i++) {
        const Elf64_Shdr *shdr = sections[i].shdr;
        if (shdr->sh_type == SHT_PROGBITS &&
                shdr->sh_flags == (SHF_ALLOC|SHF_EXECINSTR)) {
            text_shndx = i;
            break;
        }
    }

    if (!text_shndx) {
        *errmsg = ubpf_error("text section not found");
        goto error2;
    }

    struct section *text = &sections[text_shndx];

    /* Oko project */
    /* Find first .data section */
    int data_shndx = 0;
    for (i = 0; i < ehdr->e_shnum; i++) {
        const Elf64_Shdr *shdr = sections[i].shdr;
        if (shdr->sh_type == SHT_PROGBITS &&
                shdr->sh_flags == (SHF_ALLOC|SHF_WRITE)) {
            data_shndx = i;
            break;
        }
    }
    struct section *data = NULL;
    if (data_shndx) {
        data = &sections[data_shndx];
    }

    /* Find first .rodata.str section if any. */
    int str_shndx = 0;
    for (i = 0; i < ehdr->e_shnum; i++) {
        const Elf64_Shdr *shdr = sections[i].shdr;
        if (shdr->sh_type == SHT_PROGBITS &&
                shdr->sh_flags == (SHF_ALLOC|SHF_MERGE|SHF_STRINGS)) {
            str_shndx = i;
            break;
        }
    }
    struct section *str = NULL;
    if (str_shndx) {
        str = &sections[str_shndx];

        /* May need to modify text for relocations, so make a copy */
        str_copy = malloc(str->size);
        if (!str_copy) {
            *errmsg = ubpf_error("failed to allocate memory");
            goto error2;
        }
        memcpy(str_copy, str->data, str->size);
    }

    /* May need to modify text for relocations, so make a copy */
    text_copy = malloc(text->size);
    memcpy(text_copy, text->data, text->size);

    /* Process each relocation section */
    for (i = 0; i < ehdr->e_shnum; i++) {
        struct section *rel = &sections[i];
        if (rel->shdr->sh_type != SHT_REL) {
            /* NOTE: there is also SHT_RELA that we are ignoring along other
             * types */
            continue;
        } else if (rel->shdr->sh_info != text_shndx) {
            /* it is not about the .text section */
            continue;
        }

        const Elf64_Rel *rs = rel->data;
        if (rel->shdr->sh_link >= ehdr->e_shnum) {
            *errmsg = ubpf_error("bad symbol table section index");
            goto error2;
        }
        struct section *symtab = &sections[rel->shdr->sh_link];
        const Elf64_Sym *syms = symtab->data;
        uint32_t num_syms = symtab->size/sizeof(syms[0]);
        if (symtab->shdr->sh_link >= ehdr->e_shnum) {
            *errmsg = ubpf_error("bad string table section index");
            goto error2;
        }
        struct section *strtab = &sections[symtab->shdr->sh_link];
        const char *strings = strtab->data;

        int j;
        for (j = 0; j < rel->size/sizeof(Elf64_Rel); j++) {
            const Elf64_Rel *r = &rs[j];

            if (ELF64_R_TYPE(r->r_info) != ET_EXEC && ELF64_R_TYPE(r->r_info) != ET_REL) {
                *errmsg = ubpf_error("bad relocation type %u", ELF64_R_TYPE(r->r_info));
                goto error2;
            }

            uint32_t sym_idx = ELF64_R_SYM(r->r_info);
            if (sym_idx >= num_syms) {
                *errmsg = ubpf_error("bad symbol index");
                goto error2;
            }

            const Elf64_Sym *sym = &syms[sym_idx];

            if (sym->st_name >= strtab->size) {
                *errmsg = ubpf_error("bad symbol name");
                goto error2;
            }

            const char *sym_name = strings + sym->st_name;

            if (r->r_offset + 8 > text->size) {
                *errmsg = ubpf_error("bad relocation offset");
                goto error2;
            }

            /* Oko resolves the map relocations */
            switch(ELF64_R_TYPE(r->r_info)) {
                case 1:
                {
                    /* This a MAP relocation */
                    int sym_shndx = sym->st_shndx;
                    if (sym_shndx == data_shndx) {
                        if (!data_shndx) {
                            *errmsg = ubpf_error("missing data section");
                            goto error2;
                        }

                        map = ubpf_lookup_registered_map(vm, sym_name);
                        if(!map) {
                            /* If map not registered */
                            uint64_t sym_data_offset = sym->st_value;
                            if (sym_data_offset + sizeof(struct ubpf_map_def) > data->size) {
                                *errmsg = ubpf_error("bad data offset");
                                goto error2;
                            }
                            const struct ubpf_map_def *map_def = (void *)((uint64_t)data->data + sym_data_offset);

                            map = malloc(sizeof(struct ubpf_map));
                            if (initiate_map_obj(map, map_def, errmsg)) {
                                goto error_map;
                            };

                            int result = ubpf_register_map(vm, sym_name, map);
                            if (result == -1) {
                                *errmsg = ubpf_error("failed to register variable '%s'", sym_name);
                                goto error_map;
                            }
                        }

                        *(uint32_t *)((uint64_t)text_copy + r->r_offset + 4) = (uint32_t)((uint64_t)map);
                        *(uint32_t *)((uint64_t)text_copy + r->r_offset + sizeof(struct ebpf_inst) + 4) = (uint32_t)((uint64_t)map >> 32);

                    } else if (sym_shndx == str_shndx) {
                        if (!str_shndx) {
                            *errmsg = ubpf_error("missing string section");
                            goto error2;
                        }

                        uint64_t sym_data_offset = sym->st_value;
                        const char *string = (void *)((uint64_t)str_copy + sym_data_offset);
                        size_t str_len = strlen(string);
                        if (sym_data_offset + str_len > str->size) {
                            *errmsg = ubpf_error("bad data offset");
                            goto error2;
                        }

                        *(uint32_t *)((uint64_t)text_copy + r->r_offset + 4) = (uint32_t)((uint64_t)string);
                        *(uint32_t *)((uint64_t)text_copy + r->r_offset + sizeof(struct ebpf_inst) + 4) = (uint32_t)((uint64_t)string >> 32);
                    }
                    break;
                }

                case 2:
                {
                    unsigned int imm = ubpf_lookup_registered_function(vm, sym_name);
                    if (imm == -1) {
                        *errmsg = ubpf_error("function '%s' not found", sym_name);
                        goto error2;
                    }

                    *(uint32_t *)((uint64_t)text_copy + r->r_offset + 4) = imm;

                    break;
                }

                default: ;
            }
        }
    }

    /* int rv = ubpf_load(vm, text_copy, sections[text_shndx].size, errmsg); */
    for (i = 0; i < vm->sz_yield_chain; i++) {
        void *p = text_copy + progs[i].off;
        int rv = ubpf_load_prog(vm, p, progs[i].size, i, errmsg);
        if (rv != 0)
            goto error_map;
    }
    free(text_copy);
    return 0;

error_map:
    free(map);
error2:
    free(vm->insts);
    free(vm->num_insts);
    free(vm->jitted);
    free(vm->jitted_size);
error:
    free(text_copy);
    return -1;
}

struct ubpf_map *ubpf_create_map(char *name, struct ubpf_map_def *map_def,
        struct ubpf_vm *vm)
{
    struct ubpf_map *map = malloc(sizeof(struct ubpf_map));
    if (!map)
        return NULL;

    if (initiate_map_obj(map, map_def, NULL)) {
        goto error;
    };
    int result = ubpf_register_map(vm, name, map);
    if (result == -1) {
        goto error;
    }
    return map;
error:
    free(map);
    return NULL;
}
