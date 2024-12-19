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
#include <sys/mman.h>
#include "ubpf_int.h"

/* From Oko: definitions */
#define MAX_EXT_FUNCS 64
#define MAX_EXT_MAPS 64
#define NB_REGS 11

#ifndef MIN
#define MIN(X, Y) ((X) < (Y) ? (X) : (Y))
#endif
#ifndef MAX
#define MAX(X, Y) ((X) > (Y) ? (X) : (Y))
#endif

#define REGISTER_MAX_RANGE (1024 * 1024 * 1024)
#define REGISTER_MIN_RANGE -(1024 * 1024)

/* struct bpf_reg_state { */
/*     enum ubpf_reg_type type; */
/*     struct ubpf_map *map; */
/*     int64_t min_val; */
/*     uint64_t max_val; */
/* }; */

/* struct bpf_state { */
/*     struct ovs_list node; */
/*     struct bpf_reg_state regs[NB_REGS]; */
/*     struct bpf_reg_state stack[STACK_SIZE]; */
/*     uint32_t instno; */
/*     uint64_t pkt_range; */
/* }; */

/* enum vertex_status { */
/*     UNDISCOVERED = 0, */
/*     DISCOVERED, */
/*     EXPLORED, */
/* }; */

/* enum edge_status { */
/*     UNLABELED = 0, */
/*     BRANCH1_LABELED = 1, */
/*     BRANCH2_LABELED = 2, */
/* }; */

/* enum access_type { */
/*     READ = 0, */
/*     WRITE, */
/* }; */

/* ------------------------------- */

static bool validate(const struct ubpf_vm *vm, const struct ebpf_inst *insts, uint32_t num_insts, char **errmsg);
static bool bounds_check(const struct ubpf_vm *vm, void *addr, int size, const char *type, uint16_t cur_pc, void *mem, size_t mem_len, void *stack);

bool ubpf_toggle_bounds_check(struct ubpf_vm *vm, bool enable)
{
    bool old = vm->bounds_check_enabled;
    vm->bounds_check_enabled = enable;
    return old;
}

void ubpf_set_error_print(struct ubpf_vm *vm, int (*error_printf)(FILE* stream, const char* format, ...))
{
    if (error_printf)
        vm->error_printf = error_printf;
    else
        vm->error_printf = fprintf;
}

struct ubpf_vm *
ubpf_create(void)
{
    struct ubpf_vm *vm = calloc(1, sizeof(*vm));
    if (vm == NULL) {
        return NULL;
    }

    vm->ext_funcs = calloc(MAX_EXT_FUNCS, sizeof(*vm->ext_funcs));
    if (vm->ext_funcs == NULL) {
        ubpf_destroy(vm);
        return NULL;
    }

    vm->ext_func_names = calloc(MAX_EXT_FUNCS, sizeof(*vm->ext_func_names));
    if (vm->ext_func_names == NULL) {
        ubpf_destroy(vm);
        return NULL;
    }

    /* Initialize for userspace map */
    vm->ext_maps = calloc(MAX_EXT_MAPS, sizeof(*vm->ext_maps));
    if (vm->ext_maps == NULL) {
        ubpf_destroy(vm);
        return NULL;
    }

    vm->ext_map_names = calloc(MAX_EXT_MAPS, sizeof(*vm->ext_map_names));
    if (vm->ext_map_names == NULL) {
        ubpf_destroy(vm);
        return NULL;
    }

    vm->nb_maps = 0;
    /* ------------------------- */

    vm->sz_yield_chain = 0;
    vm->insts = NULL;
    vm->num_insts = NULL;
    vm->jitted = NULL;
    vm->jitted_size = NULL;

    vm->bounds_check_enabled = true;
    vm->error_printf = fprintf;

    vm->unwind_stack_extension_index = -1;
    return vm;
}

void
ubpf_destroy(struct ubpf_vm *vm)
{
    for (int i = 0; i < vm->nb_maps; i++) {
        free(vm->ext_maps[i]);
        free((void *)vm->ext_map_names[i]);
    }
    for (int i = 0; i < vm->sz_yield_chain; i++) {
        free(vm->insts[i]);
        if (vm->jitted) {
            munmap(vm->jitted[i], vm->jitted_size[i]);
        }
    }
    free(vm->insts);
    free(vm->num_insts);
    free(vm->ext_funcs);
    free(vm->ext_func_names);
    free(vm->ext_maps);
    free(vm->ext_map_names);
    free(vm->jitted);
    free(vm->jitted_size);
    free(vm);
}

int
ubpf_register(struct ubpf_vm *vm, unsigned int idx, const char *name, void *fn)
{
    if (idx >= MAX_EXT_FUNCS) {
        return -1;
    }

    vm->ext_funcs[idx] = (ext_func)fn;
    vm->ext_func_names[idx] = name;

    return 0;
}

/* From Oko project */
int
ubpf_register_map(struct ubpf_vm *vm, const char *name, struct ubpf_map *map)
{
    unsigned int idx = vm->nb_maps;
    if (idx >= MAX_EXT_MAPS) {
        return -1;
    }
    vm->ext_maps[idx] = map;
    vm->ext_map_names[idx] = strndup(name, 31);
    vm->nb_maps++;
    return 0;
}
/* ----------------- */

int ubpf_set_unwind_function_index(struct ubpf_vm *vm, unsigned int idx)
{
    if (vm->unwind_stack_extension_index != -1) {
        return -1;
    }

    vm->unwind_stack_extension_index = idx;
    return 0;
}

unsigned int
ubpf_lookup_registered_function(struct ubpf_vm *vm, const char *name)
{
    int i;
    for (i = 0; i < MAX_EXT_FUNCS; i++) {
        const char *other = vm->ext_func_names[i];
        if (other && !strcmp(other, name)) {
            return i;
        }
    }
    return -1;
}

/* From Oko project */
struct ubpf_map *
ubpf_lookup_registered_map(struct ubpf_vm *vm, const char *name)
{
    int i;
    for (i = 0; i < MAX_EXT_MAPS; i++) {
        const char *other = vm->ext_map_names[i];
        if (other && !strcmp(other, name)) {
            return vm->ext_maps[i];
        }
    }
    return NULL;
}
/* ---------------- */

int
ubpf_load(struct ubpf_vm *vm, const void *code, uint32_t code_len, char **errmsg)
{
    *errmsg = NULL;

    if (vm->insts) {
        *errmsg = ubpf_error("code has already been loaded into this VM");
        return -1;
    }

    if (code_len % 8 != 0) {
        *errmsg = ubpf_error("code_len must be a multiple of 8");
        return -1;
    }

    if (!validate(vm, code, code_len/8, errmsg)) {
        return -1;
    }

    vm->sz_yield_chain = 1;
    vm->insts = malloc(sizeof(void *));
    vm->num_insts = malloc(sizeof(uint16_t));
    vm->insts[0] = malloc(code_len);
    if (vm->insts == NULL) {
        *errmsg = ubpf_error("out of memory");
        return -1;
    }

    memcpy(vm->insts[0], code, code_len);
    vm->num_insts[0] = code_len/sizeof(vm->insts[0][0]);

    return 0;
}

int
ubpf_load_prog(struct ubpf_vm *vm, const void *code, uint32_t code_len,
        uint16_t prog_index, char **errmsg)
{
    *errmsg = NULL;

    if (prog_index >= vm->sz_yield_chain) {
        *errmsg = ubpf_error("program index out of range");
        return -1;
    }

    if (!vm->insts) {
        *errmsg = ubpf_error("internal error: insts array is not initialized");
        return -1;
    }

    if (vm->insts[prog_index] != NULL) {
        *errmsg = ubpf_error("code has already been loaded into this VM (at program index: %d)", prog_index);
        return -1;
    }

    if (code_len % 8 != 0) {
        *errmsg = ubpf_error("code_len must be a multiple of 8");
        return -1;
    }

    if (!validate(vm, code, code_len/8, errmsg)) {
        return -1;
    }

    void *p = malloc(code_len);
    if (p == NULL) {
        *errmsg = ubpf_error("out of memory");
        return -1;
    }
    vm->insts[prog_index] = p;
    memcpy(p, code, code_len);
    vm->num_insts[prog_index] = code_len / sizeof(vm->insts[prog_index][0]);
    return 0;
}

static uint32_t
u32(uint64_t x)
{
    return x;
}

int
ubpf_exec(const struct ubpf_vm *vm, void *mem, size_t mem_len,
        uint64_t* bpf_return_value)
{
    if (vm->sz_yield_chain < 1 || !vm->insts)
        return -1;

    uint16_t pc = 0;
    const struct ebpf_inst *insts = vm->insts[0];
    uint64_t reg[16];
    uint64_t stack[(UBPF_STACK_SIZE+7)/8];

    if (!insts) {
        /* Code must be loaded before we can execute */
        return -1;
    }

    reg[1] = (uintptr_t)mem;
    reg[2] = (uint64_t)mem_len;
    reg[10] = (uintptr_t)stack + sizeof(stack);

    while (1) {
        const uint16_t cur_pc = pc;
        struct ebpf_inst inst = insts[pc++];

        switch (inst.opcode) {
        case EBPF_OP_ADD_IMM:
            reg[inst.dst] += inst.imm;
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_ADD_REG:
            reg[inst.dst] += reg[inst.src];
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_SUB_IMM:
            reg[inst.dst] -= inst.imm;
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_SUB_REG:
            reg[inst.dst] -= reg[inst.src];
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_MUL_IMM:
            reg[inst.dst] *= inst.imm;
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_MUL_REG:
            reg[inst.dst] *= reg[inst.src];
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_DIV_IMM:
            reg[inst.dst] = u32(reg[inst.dst]) / u32(inst.imm);
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_DIV_REG:
            if (reg[inst.src] == 0) {
                vm->error_printf(stderr, "uBPF error: division by zero at PC %u\n", cur_pc);
                return -1;
            }
            reg[inst.dst] = u32(reg[inst.dst]) / u32(reg[inst.src]);
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_OR_IMM:
            reg[inst.dst] |= inst.imm;
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_OR_REG:
            reg[inst.dst] |= reg[inst.src];
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_AND_IMM:
            reg[inst.dst] &= inst.imm;
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_AND_REG:
            reg[inst.dst] &= reg[inst.src];
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_LSH_IMM:
            reg[inst.dst] <<= inst.imm;
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_LSH_REG:
            reg[inst.dst] <<= reg[inst.src];
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_RSH_IMM:
            reg[inst.dst] = u32(reg[inst.dst]) >> inst.imm;
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_RSH_REG:
            reg[inst.dst] = u32(reg[inst.dst]) >> reg[inst.src];
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_NEG:
            reg[inst.dst] = -(int64_t)reg[inst.dst];
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_MOD_IMM:
            reg[inst.dst] = u32(reg[inst.dst]) % u32(inst.imm);
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_MOD_REG:
            if (reg[inst.src] == 0) {
                vm->error_printf(stderr, "uBPF error: division by zero at PC %u\n", cur_pc);
                return -1;
            }
            reg[inst.dst] = u32(reg[inst.dst]) % u32(reg[inst.src]);
            break;
        case EBPF_OP_XOR_IMM:
            reg[inst.dst] ^= inst.imm;
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_XOR_REG:
            reg[inst.dst] ^= reg[inst.src];
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_MOV_IMM:
            reg[inst.dst] = inst.imm;
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_MOV_REG:
            reg[inst.dst] = reg[inst.src];
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_ARSH_IMM:
            reg[inst.dst] = (int32_t)reg[inst.dst] >> inst.imm;
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_ARSH_REG:
            reg[inst.dst] = (int32_t)reg[inst.dst] >> u32(reg[inst.src]);
            reg[inst.dst] &= UINT32_MAX;
            break;

        case EBPF_OP_LE:
            if (inst.imm == 16) {
                reg[inst.dst] = htole16(reg[inst.dst]);
            } else if (inst.imm == 32) {
                reg[inst.dst] = htole32(reg[inst.dst]);
            } else if (inst.imm == 64) {
                reg[inst.dst] = htole64(reg[inst.dst]);
            }
            break;
        case EBPF_OP_BE:
            if (inst.imm == 16) {
                reg[inst.dst] = htobe16(reg[inst.dst]);
            } else if (inst.imm == 32) {
                reg[inst.dst] = htobe32(reg[inst.dst]);
            } else if (inst.imm == 64) {
                reg[inst.dst] = htobe64(reg[inst.dst]);
            }
            break;


        case EBPF_OP_ADD64_IMM:
            reg[inst.dst] += inst.imm;
            break;
        case EBPF_OP_ADD64_REG:
            reg[inst.dst] += reg[inst.src];
            break;
        case EBPF_OP_SUB64_IMM:
            reg[inst.dst] -= inst.imm;
            break;
        case EBPF_OP_SUB64_REG:
            reg[inst.dst] -= reg[inst.src];
            break;
        case EBPF_OP_MUL64_IMM:
            reg[inst.dst] *= inst.imm;
            break;
        case EBPF_OP_MUL64_REG:
            reg[inst.dst] *= reg[inst.src];
            break;
        case EBPF_OP_DIV64_IMM:
            reg[inst.dst] /= inst.imm;
            break;
        case EBPF_OP_DIV64_REG:
            if (reg[inst.src] == 0) {
                vm->error_printf(stderr, "uBPF error: division by zero at PC %u\n", cur_pc);
                return -1;
            }
            reg[inst.dst] /= reg[inst.src];
            break;
        case EBPF_OP_OR64_IMM:
            reg[inst.dst] |= inst.imm;
            break;
        case EBPF_OP_OR64_REG:
            reg[inst.dst] |= reg[inst.src];
            break;
        case EBPF_OP_AND64_IMM:
            reg[inst.dst] &= inst.imm;
            break;
        case EBPF_OP_AND64_REG:
            reg[inst.dst] &= reg[inst.src];
            break;
        case EBPF_OP_LSH64_IMM:
            reg[inst.dst] <<= inst.imm;
            break;
        case EBPF_OP_LSH64_REG:
            reg[inst.dst] <<= reg[inst.src];
            break;
        case EBPF_OP_RSH64_IMM:
            reg[inst.dst] >>= inst.imm;
            break;
        case EBPF_OP_RSH64_REG:
            reg[inst.dst] >>= reg[inst.src];
            break;
        case EBPF_OP_NEG64:
            reg[inst.dst] = -reg[inst.dst];
            break;
        case EBPF_OP_MOD64_IMM:
            reg[inst.dst] %= inst.imm;
            break;
        case EBPF_OP_MOD64_REG:
            if (reg[inst.src] == 0) {
                vm->error_printf(stderr, "uBPF error: division by zero at PC %u\n", cur_pc);
                return -1;
            }
            reg[inst.dst] %= reg[inst.src];
            break;
        case EBPF_OP_XOR64_IMM:
            reg[inst.dst] ^= inst.imm;
            break;
        case EBPF_OP_XOR64_REG:
            reg[inst.dst] ^= reg[inst.src];
            break;
        case EBPF_OP_MOV64_IMM:
            reg[inst.dst] = inst.imm;
            break;
        case EBPF_OP_MOV64_REG:
            reg[inst.dst] = reg[inst.src];
            break;
        case EBPF_OP_ARSH64_IMM:
            reg[inst.dst] = (int64_t)reg[inst.dst] >> inst.imm;
            break;
        case EBPF_OP_ARSH64_REG:
            reg[inst.dst] = (int64_t)reg[inst.dst] >> reg[inst.src];
            break;

        /*
         * HACK runtime bounds check
         *
         * Needed since we don't have a verifier yet.
         */
#define BOUNDS_CHECK_LOAD(size) \
    do { \
        if (!bounds_check(vm, (char *)reg[inst.src] + inst.offset, size, "load", cur_pc, mem, mem_len, stack)) { \
            return -1; \
        } \
    } while (0)
#define BOUNDS_CHECK_STORE(size) \
    do { \
        if (!bounds_check(vm, (char *)reg[inst.dst] + inst.offset, size, "store", cur_pc, mem, mem_len, stack)) { \
            return -1; \
        } \
    } while (0)

        case EBPF_OP_LDXW:
            BOUNDS_CHECK_LOAD(4);
            reg[inst.dst] = *(uint32_t *)(uintptr_t)(reg[inst.src] + inst.offset);
            break;
        case EBPF_OP_LDXH:
            BOUNDS_CHECK_LOAD(2);
            reg[inst.dst] = *(uint16_t *)(uintptr_t)(reg[inst.src] + inst.offset);
            break;
        case EBPF_OP_LDXB:
            BOUNDS_CHECK_LOAD(1);
            reg[inst.dst] = *(uint8_t *)(uintptr_t)(reg[inst.src] + inst.offset);
            break;
        case EBPF_OP_LDXDW:
            BOUNDS_CHECK_LOAD(8);
            reg[inst.dst] = *(uint64_t *)(uintptr_t)(reg[inst.src] + inst.offset);
            break;

        case EBPF_OP_STW:
            BOUNDS_CHECK_STORE(4);
            *(uint32_t *)(uintptr_t)(reg[inst.dst] + inst.offset) = inst.imm;
            break;
        case EBPF_OP_STH:
            BOUNDS_CHECK_STORE(2);
            *(uint16_t *)(uintptr_t)(reg[inst.dst] + inst.offset) = inst.imm;
            break;
        case EBPF_OP_STB:
            BOUNDS_CHECK_STORE(1);
            *(uint8_t *)(uintptr_t)(reg[inst.dst] + inst.offset) = inst.imm;
            break;
        case EBPF_OP_STDW:
            BOUNDS_CHECK_STORE(8);
            *(uint64_t *)(uintptr_t)(reg[inst.dst] + inst.offset) = inst.imm;
            break;

        case EBPF_OP_STXW:
            BOUNDS_CHECK_STORE(4);
            *(uint32_t *)(uintptr_t)(reg[inst.dst] + inst.offset) = reg[inst.src];
            break;
        case EBPF_OP_STXH:
            BOUNDS_CHECK_STORE(2);
            *(uint16_t *)(uintptr_t)(reg[inst.dst] + inst.offset) = reg[inst.src];
            break;
        case EBPF_OP_STXB:
            BOUNDS_CHECK_STORE(1);
            *(uint8_t *)(uintptr_t)(reg[inst.dst] + inst.offset) = reg[inst.src];
            break;
        case EBPF_OP_STXDW:
            BOUNDS_CHECK_STORE(8);
            *(uint64_t *)(uintptr_t)(reg[inst.dst] + inst.offset) = reg[inst.src];
            break;

        case EBPF_OP_LDDW:
            reg[inst.dst] = (uint32_t)inst.imm | ((uint64_t)insts[pc++].imm << 32);
            break;

        case EBPF_OP_JA:
            pc += inst.offset;
            break;
        case EBPF_OP_JEQ_IMM:
            if (reg[inst.dst] == inst.imm) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JEQ_REG:
            if (reg[inst.dst] == reg[inst.src]) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JGT_IMM:
            if (reg[inst.dst] > (uint32_t)inst.imm) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JGT_REG:
            if (reg[inst.dst] > reg[inst.src]) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JGE_IMM:
            if (reg[inst.dst] >= (uint32_t)inst.imm) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JGE_REG:
            if (reg[inst.dst] >= reg[inst.src]) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JLT_IMM:
            if (reg[inst.dst] < (uint32_t)inst.imm) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JLT_REG:
            if (reg[inst.dst] < reg[inst.src]) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JLE_IMM:
            if (reg[inst.dst] <= (uint32_t)inst.imm) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JLE_REG:
            if (reg[inst.dst] <= reg[inst.src]) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JSET_IMM:
            if (reg[inst.dst] & inst.imm) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JSET_REG:
            if (reg[inst.dst] & reg[inst.src]) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JNE_IMM:
            if (reg[inst.dst] != inst.imm) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JNE_REG:
            if (reg[inst.dst] != reg[inst.src]) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JSGT_IMM:
            if ((int64_t)reg[inst.dst] > inst.imm) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JSGT_REG:
            if ((int64_t)reg[inst.dst] > (int64_t)reg[inst.src]) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JSGE_IMM:
            if ((int64_t)reg[inst.dst] >= inst.imm) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JSGE_REG:
            if ((int64_t)reg[inst.dst] >= (int64_t)reg[inst.src]) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JSLT_IMM:
            if ((int64_t)reg[inst.dst] < inst.imm) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JSLT_REG:
            if ((int64_t)reg[inst.dst] < (int64_t)reg[inst.src]) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JSLE_IMM:
            if ((int64_t)reg[inst.dst] <= inst.imm) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JSLE_REG:
            if ((int64_t)reg[inst.dst] <= (int64_t)reg[inst.src]) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_EXIT:
            *bpf_return_value = reg[0];
            return 0;
        case EBPF_OP_CALL:
            reg[0] = vm->ext_funcs[inst.imm](reg[1], reg[2], reg[3], reg[4], reg[5]);
            // Unwind the stack if unwind extension returns success.
            if (inst.imm == vm->unwind_stack_extension_index && reg[0] == 0) {
                *bpf_return_value = reg[0];
                return 0;
            }
            break;
        }
    }
}

static bool
validate(const struct ubpf_vm *vm, const struct ebpf_inst *insts, uint32_t num_insts, char **errmsg)
{
    if (num_insts >= UBPF_MAX_INSTS) {
        *errmsg = ubpf_error("too many instructions (max %u)", UBPF_MAX_INSTS);
        return false;
    }

    int i;
    for (i = 0; i < num_insts; i++) {
        struct ebpf_inst inst = insts[i];
        bool store = false;

        switch (inst.opcode) {
        case EBPF_OP_ADD_IMM:
        case EBPF_OP_ADD_REG:
        case EBPF_OP_SUB_IMM:
        case EBPF_OP_SUB_REG:
        case EBPF_OP_MUL_IMM:
        case EBPF_OP_MUL_REG:
        case EBPF_OP_DIV_REG:
        case EBPF_OP_OR_IMM:
        case EBPF_OP_OR_REG:
        case EBPF_OP_AND_IMM:
        case EBPF_OP_AND_REG:
        case EBPF_OP_LSH_IMM:
        case EBPF_OP_LSH_REG:
        case EBPF_OP_RSH_IMM:
        case EBPF_OP_RSH_REG:
        case EBPF_OP_NEG:
        case EBPF_OP_MOD_REG:
        case EBPF_OP_XOR_IMM:
        case EBPF_OP_XOR_REG:
        case EBPF_OP_MOV_IMM:
        case EBPF_OP_MOV_REG:
        case EBPF_OP_ARSH_IMM:
        case EBPF_OP_ARSH_REG:
            break;

        case EBPF_OP_LE:
        case EBPF_OP_BE:
            if (inst.imm != 16 && inst.imm != 32 && inst.imm != 64) {
                *errmsg = ubpf_error("invalid endian immediate at PC %d", i);
                return false;
            }
            break;

        case EBPF_OP_ADD64_IMM:
        case EBPF_OP_ADD64_REG:
        case EBPF_OP_SUB64_IMM:
        case EBPF_OP_SUB64_REG:
        case EBPF_OP_MUL64_IMM:
        case EBPF_OP_MUL64_REG:
        case EBPF_OP_DIV64_REG:
        case EBPF_OP_OR64_IMM:
        case EBPF_OP_OR64_REG:
        case EBPF_OP_AND64_IMM:
        case EBPF_OP_AND64_REG:
        case EBPF_OP_LSH64_IMM:
        case EBPF_OP_LSH64_REG:
        case EBPF_OP_RSH64_IMM:
        case EBPF_OP_RSH64_REG:
        case EBPF_OP_NEG64:
        case EBPF_OP_MOD64_REG:
        case EBPF_OP_XOR64_IMM:
        case EBPF_OP_XOR64_REG:
        case EBPF_OP_MOV64_IMM:
        case EBPF_OP_MOV64_REG:
        case EBPF_OP_ARSH64_IMM:
        case EBPF_OP_ARSH64_REG:
            break;

        case EBPF_OP_LDXW:
        case EBPF_OP_LDXH:
        case EBPF_OP_LDXB:
        case EBPF_OP_LDXDW:
            break;

        case EBPF_OP_STW:
        case EBPF_OP_STH:
        case EBPF_OP_STB:
        case EBPF_OP_STDW:
        case EBPF_OP_STXW:
        case EBPF_OP_STXH:
        case EBPF_OP_STXB:
        case EBPF_OP_STXDW:
            store = true;
            break;

        case EBPF_OP_LDDW:
            if (i + 1 >= num_insts || insts[i+1].opcode != 0) {
                *errmsg = ubpf_error("incomplete lddw at PC %d", i);
                return false;
            }
            i++; /* Skip next instruction */
            break;

        case EBPF_OP_JA:
        case EBPF_OP_JEQ_REG:
        case EBPF_OP_JEQ_IMM:
        case EBPF_OP_JGT_REG:
        case EBPF_OP_JGT_IMM:
        case EBPF_OP_JGE_REG:
        case EBPF_OP_JGE_IMM:
        case EBPF_OP_JLT_REG:
        case EBPF_OP_JLT_IMM:
        case EBPF_OP_JLE_REG:
        case EBPF_OP_JLE_IMM:
        case EBPF_OP_JSET_REG:
        case EBPF_OP_JSET_IMM:
        case EBPF_OP_JNE_REG:
        case EBPF_OP_JNE_IMM:
        case EBPF_OP_JSGT_IMM:
        case EBPF_OP_JSGT_REG:
        case EBPF_OP_JSGE_IMM:
        case EBPF_OP_JSGE_REG:
        case EBPF_OP_JSLT_IMM:
        case EBPF_OP_JSLT_REG:
        case EBPF_OP_JSLE_IMM:
        case EBPF_OP_JSLE_REG:
        /* JMP32 */
        case EBPF_OP_JEQ32_REG:
        case EBPF_OP_JEQ32_IMM:
        case EBPF_OP_JGT32_REG:
        case EBPF_OP_JGT32_IMM:
        case EBPF_OP_JGE32_REG:
        case EBPF_OP_JGE32_IMM:
        case EBPF_OP_JLT32_REG:
        case EBPF_OP_JLT32_IMM:
        case EBPF_OP_JLE32_REG:
        case EBPF_OP_JLE32_IMM:
        case EBPF_OP_JSET32_REG:
        case EBPF_OP_JSET32_IMM:
        case EBPF_OP_JNE32_REG:
        case EBPF_OP_JNE32_IMM:
        case EBPF_OP_JSGT32_IMM:
        case EBPF_OP_JSGT32_REG:
        case EBPF_OP_JSGE32_IMM:
        case EBPF_OP_JSGE32_REG:
        case EBPF_OP_JSLT32_IMM:
        case EBPF_OP_JSLT32_REG:
        case EBPF_OP_JSLE32_IMM:
        case EBPF_OP_JSLE32_REG:
            if (inst.offset == -1) {
                *errmsg = ubpf_error("infinite loop at PC %d", i);
                return false;
            }
            int new_pc = i + 1 + inst.offset;
            if (new_pc < 0 || new_pc >= num_insts) {
                *errmsg = ubpf_error("jump out of bounds at PC %d", i);
                return false;
            } else if (insts[new_pc].opcode == 0) {
                *errmsg = ubpf_error("jump to middle of lddw at PC %d", i);
                return false;
            }
            break;

        case EBPF_OP_CALL:
            if (inst.imm < 0 || inst.imm >= MAX_EXT_FUNCS) {
                *errmsg = ubpf_error("invalid call immediate at PC %d", i);
                return false;
            }
            if (!vm->ext_funcs[inst.imm]) {
                *errmsg = ubpf_error("call to nonexistent function %u at PC %d", inst.imm, i);
                return false;
            }
            break;

        case EBPF_OP_EXIT:
            break;

        case EBPF_OP_DIV_IMM:
        case EBPF_OP_MOD_IMM:
        case EBPF_OP_DIV64_IMM:
        case EBPF_OP_MOD64_IMM:
            if (inst.imm == 0) {
                *errmsg = ubpf_error("division by zero at PC %d", i);
                return false;
            }
            break;

        /* Atomic Operations */
        case EBPF_OP_AT_4:
        case EBPF_OP_AT_8:
            break;

        default:
            *errmsg = ubpf_error("unknown opcode 0x%02x at PC %d", inst.opcode, i);
            return false;
        }

        if (inst.src > 10) {
            *errmsg = ubpf_error("invalid source register at PC %d", i);
            return false;
        }

        if (inst.dst > 9 && !(store && inst.dst == 10)) {
            *errmsg = ubpf_error("invalid destination register at PC %d", i);
            return false;
        }
    }

    return true;
}

static bool
bounds_check(const struct ubpf_vm *vm, void *addr, int size, const char *type, uint16_t cur_pc, void *mem, size_t mem_len, void *stack)
{
    if (!vm->bounds_check_enabled)
        return true;
    if (mem && (addr >= mem && ((char*)addr + size) <= ((char*)mem + mem_len))) {
        /* Context access */
        return true;
    } else if (addr >= stack && ((char*)addr + size) <= ((char*)stack + UBPF_STACK_SIZE)) {
        /* Stack access */
        return true;
    } else {
        vm->error_printf(stderr, "uBPF error: out of bounds memory %s at PC %u, addr %p, size %d\nmem %p/%zd stack %p/%d\n", type, cur_pc, addr, size, mem, mem_len, stack, UBPF_STACK_SIZE);
        return false;
    }
}

char *
ubpf_error(const char *fmt, ...)
{
    char *msg;
    va_list ap;
    va_start(ap, fmt);
    if (vasprintf(&msg, fmt, ap) < 0) {
        msg = NULL;
    }
    va_end(ap);
    return msg;
}

/* This is used to support overlapping lookup procedure with processing of a
 * batch of packets
 * */
static int batch_size_mask = 64 - 1;
static int batch_size_half = 32;
int offset_in_batch;
yield_state_t yield_state[MAX_BATCH_SZ] = {};

int ubpf_set_batch_size(int batch) {
    if (batch > MAX_BATCH_SZ)
        return -1;
    if ((batch & (batch - 1)) != 0) {
        // must be power of two
        return -1;
    }
    batch_size_mask = batch-1;
    batch_size_half = batch / 2;
    return 0;
}


#include "utils/openvswitch/list.h"
void ubpf_set_batch_offset(int off)
{
    offset_in_batch = off;
    /* __builtin_prefetch(yield_state + off); */

    /* We have prefetched the bucket in phase 1, lets fetch the key now. If we
     * fetch the key when we are at stage 2 and want to proces the 2nd-phase it
     * might be too late. So lets overlap fetching the keys (after waiting some
     * time so that bucket is in the cache) with fetching the bucket of other
     * keys.
     * */
    uint32_t o = (off + batch_size_half) & batch_size_mask;
    if (yield_state[o].p1_flag) {
        struct ovs_list *ovs_list_head = yield_state[o].head;
        /* if (ovs_list_head != NULL) */
            __builtin_prefetch(ovs_list_head->next); // fetch next elem
    }
}

/* Userspace map API for control-plane applications */
struct ubpf_map *ubpf_select_map(char *name, struct ubpf_vm *vm)
{
    for (int i = 0; i < vm->nb_maps; i++) {
        if (!strcmp(vm->ext_map_names[i], name))
            return vm->ext_maps[i];
    }
    return NULL;
}

void *ubpf_lookup_map(struct ubpf_map* map, void *key)
{
    if (!map) {
        /* printf("no map!\n"); */
        return NULL;
    }
    if (!map->ops.map_lookup) {
        /* printf("no ops!\n"); */
        return NULL;
    }
    if (!key) {
        /* printf("no key\n"); */
        return NULL;
    }
    return map->ops.map_lookup(map, key);
}

void ubpf_hashmap_lookup_p1(const struct ubpf_map *map, const void *key);
void * ubpf_hashmap_lookup_p2(const struct ubpf_map *map, void *key);

int
ubpf_lookup_map_p1(const struct ubpf_map *map, const void *key)
{
    if (!map || !key || !map->ops.map_lookup_p1) {
        return -1;
    }
    if (map->type == UBPF_MAP_TYPE_HASHMAP) {
        ubpf_hashmap_lookup_p1(map, key);
    } else {
        map->ops.map_lookup_p1(map, key);
    }
    return 0;
}

void *
ubpf_lookup_map_p2(const struct ubpf_map *map, void *key)
{
    if (!map || !key || !map->ops.map_lookup_p2) {
        return NULL;
    }
    if (map->type == UBPF_MAP_TYPE_HASHMAP) {
        return ubpf_hashmap_lookup_p2(map, key);
    } else {
        return map->ops.map_lookup_p2(map, key);
    }
}

int ubpf_update_map(struct ubpf_map* map, void *key, void *value)
{
    if (!map)
        return -1;
    if (!map->ops.map_update)
        return -2;
    if (!key)
        return -3;
    if (!value)
        return -4;
    return map->ops.map_update(map, key, value);
}
/* ---------------------------------------- */
