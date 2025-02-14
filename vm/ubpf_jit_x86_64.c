/*
 * Copyright 2015 Big Switch Networks, Inc
 * Copyright 2017 Google Inc.
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
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/mman.h>
#include <errno.h>
#include <assert.h>
#include <elf.h>
#include "ubpf_int.h"
#include "ubpf_jit_x86_64.h"
#include "ubpf_debug_info.h"

/* Special valus for target_pc in struct jump */
#define TARGET_PC_EXIT -1
#define TARGET_PC_DIV_BY_ZERO -2

#if !defined(_countof)
#define _countof(array) (sizeof(array) / sizeof(array[0]))
#endif

/* Special values for target_pc in struct jump */
#define TARGET_PC_EXIT -1
#define TARGET_PC_DIV_BY_ZERO -2

static void muldivmod(struct jit_state *state, uint16_t pc, uint8_t opcode, int src, int dst, int32_t imm);

#define REGISTER_MAP_SIZE 11

/*
 * There are two common x86-64 calling conventions, as discussed at
 * https://en.wikipedia.org/wiki/X86_calling_conventions#x86-64_calling_conventions
 */

#if defined(_WIN32)
static int platform_nonvolatile_registers[] = {
    RBP, RBX, RDI, RSI, R12, R13, R14, R15
};
static int platform_parameter_registers[] = {
    RCX, RDX, R8, R9
};
#define RCX_ALT R10
// Register assignments:
// BPF R0-R4 are "volatile"
// BPF R5-R10 are "non-volatile"
// Map BPF volatile registers to x64 volatile and map BPF non-volatile to
// x64 non-volatile.
// Avoid R12 as we don't support encoding modrm modifier for using R12.
static int register_map[REGISTER_MAP_SIZE] = {
    RAX,
    R10,
    RDX,
    R8,
    R9,
    R14,
    R15,
    RDI,
    RSI,
    RBX,
    RBP,
};
#else
#define RCX_ALT R9
static int platform_nonvolatile_registers[] = {
    RBP, RBX, R13, R14, R15
};
static int platform_parameter_registers[] = {
    RDI, RSI, RDX, RCX, R8, R9
};
static int register_map[REGISTER_MAP_SIZE] = {
    RAX,
    RDI,
    RSI,
    RDX,
    R9,
    R8,
    RBX,
    R13,
    R14,
    R15,
    RBP,
};
#endif

/* Return the x86 register for the given eBPF register */
static int
map_register(int r)
{
    assert(r < REGISTER_MAP_SIZE);
    return register_map[r % REGISTER_MAP_SIZE];
}

/* For testing, this changes the mapping between x86 and eBPF registers */
void
ubpf_set_register_offset(int x)
{
    int i;
    if (x < REGISTER_MAP_SIZE) {
        int tmp[REGISTER_MAP_SIZE];
        memcpy(tmp, register_map, sizeof(register_map));
        for (i = 0; i < REGISTER_MAP_SIZE; i++) {
            register_map[i] = tmp[(i+x)%REGISTER_MAP_SIZE];
        }
    } else {
        /* Shuffle array */
        unsigned int seed = x;
        for (i = 0; i < REGISTER_MAP_SIZE-1; i++) {
            int j = i + (rand_r(&seed) % (REGISTER_MAP_SIZE-i));
            int tmp = register_map[j];
            register_map[j] = register_map[i];
            register_map[i] = tmp;
        }
    }
}

static int
translate(struct ubpf_vm *vm, struct jit_state *state,
        struct ebpf_inst *insts, size_t num_insts, char **errmsg)
{
    int i;

    /* Save platform non-volatile registers */
    for (i = 0; i < _countof(platform_nonvolatile_registers); i++)
    {
        emit_push(state, platform_nonvolatile_registers[i]);
    }

    /* Move first platform parameter register into register 1 */
    if (map_register(1) != platform_parameter_registers[0]) {
        emit_mov(state, platform_parameter_registers[0], map_register(1));
    }

    /* Copy stack pointer to R10 */
    emit_mov(state, RSP, map_register(10));

    /* Allocate stack space */
    emit_alu64_imm32(state, 0x81, 5, RSP, UBPF_STACK_SIZE);

    for (i = 0; i < num_insts; i++) {
        struct ebpf_inst inst = insts[i];
        state->pc_locs[i] = state->offset;

        int dst = map_register(inst.dst);
        int src = map_register(inst.src);
        uint32_t target_pc = i + inst.offset + 1;

        switch (inst.opcode) {
        case EBPF_OP_ADD_IMM:
            emit_alu32_imm32(state, 0x81, 0, dst, inst.imm);
            break;
        case EBPF_OP_ADD_REG:
            emit_alu32(state, 0x01, src, dst);
            break;
        case EBPF_OP_SUB_IMM:
            emit_alu32_imm32(state, 0x81, 5, dst, inst.imm);
            break;
        case EBPF_OP_SUB_REG:
            emit_alu32(state, 0x29, src, dst);
            break;
        case EBPF_OP_MUL_IMM:
        case EBPF_OP_MUL_REG:
        case EBPF_OP_DIV_IMM:
        case EBPF_OP_DIV_REG:
        case EBPF_OP_MOD_IMM:
        case EBPF_OP_MOD_REG:
            muldivmod(state, i, inst.opcode, src, dst, inst.imm);
            break;
        case EBPF_OP_OR_IMM:
            emit_alu32_imm32(state, 0x81, 1, dst, inst.imm);
            break;
        case EBPF_OP_OR_REG:
            emit_alu32(state, 0x09, src, dst);
            break;
        case EBPF_OP_AND_IMM:
            emit_alu32_imm32(state, 0x81, 4, dst, inst.imm);
            break;
        case EBPF_OP_AND_REG:
            emit_alu32(state, 0x21, src, dst);
            break;
        case EBPF_OP_LSH_IMM:
            emit_alu32_imm8(state, 0xc1, 4, dst, inst.imm);
            break;
        case EBPF_OP_LSH_REG:
            emit_mov(state, src, RCX);
            emit_alu32(state, 0xd3, 4, dst);
            break;
        case EBPF_OP_RSH_IMM:
            emit_alu32_imm8(state, 0xc1, 5, dst, inst.imm);
            break;
        case EBPF_OP_RSH_REG:
            emit_mov(state, src, RCX);
            emit_alu32(state, 0xd3, 5, dst);
            break;
        case EBPF_OP_NEG:
            emit_alu32(state, 0xf7, 3, dst);
            break;
        case EBPF_OP_XOR_IMM:
            emit_alu32_imm32(state, 0x81, 6, dst, inst.imm);
            break;
        case EBPF_OP_XOR_REG:
            emit_alu32(state, 0x31, src, dst);
            break;
        case EBPF_OP_MOV_IMM:
            emit_alu32_imm32(state, 0xc7, 0, dst, inst.imm);
            break;
        case EBPF_OP_MOV_REG:
            emit_mov(state, src, dst);
            break;
        case EBPF_OP_ARSH_IMM:
            emit_alu32_imm8(state, 0xc1, 7, dst, inst.imm);
            break;
        case EBPF_OP_ARSH_REG:
            emit_mov(state, src, RCX);
            emit_alu32(state, 0xd3, 7, dst);
            break;

        case EBPF_OP_LE:
            /* No-op */
            break;
        case EBPF_OP_BE:
            if (inst.imm == 16) {
                /* rol */
                emit1(state, 0x66); /* 16-bit override */
                emit_alu32_imm8(state, 0xc1, 0, dst, 8);
                /* and */
                emit_alu32_imm32(state, 0x81, 4, dst, 0xffff);
            } else if (inst.imm == 32 || inst.imm == 64) {
                /* bswap */
                emit_basic_rex(state, inst.imm == 64, 0, dst);
                emit1(state, 0x0f);
                emit1(state, 0xc8 | (dst & 7));
            }
            break;

        case EBPF_OP_ADD64_IMM:
            emit_alu64_imm32(state, 0x81, 0, dst, inst.imm);
            break;
        case EBPF_OP_ADD64_REG:
            emit_alu64(state, 0x01, src, dst);
            break;
        case EBPF_OP_SUB64_IMM:
            emit_alu64_imm32(state, 0x81, 5, dst, inst.imm);
            break;
        case EBPF_OP_SUB64_REG:
            emit_alu64(state, 0x29, src, dst);
            break;
        case EBPF_OP_MUL64_IMM:
        case EBPF_OP_MUL64_REG:
        case EBPF_OP_DIV64_IMM:
        case EBPF_OP_DIV64_REG:
        case EBPF_OP_MOD64_IMM:
        case EBPF_OP_MOD64_REG:
            muldivmod(state, i, inst.opcode, src, dst, inst.imm);
            break;
        case EBPF_OP_OR64_IMM:
            emit_alu64_imm32(state, 0x81, 1, dst, inst.imm);
            break;
        case EBPF_OP_OR64_REG:
            emit_alu64(state, 0x09, src, dst);
            break;
        case EBPF_OP_AND64_IMM:
            emit_alu64_imm32(state, 0x81, 4, dst, inst.imm);
            break;
        case EBPF_OP_AND64_REG:
            emit_alu64(state, 0x21, src, dst);
            break;
        case EBPF_OP_LSH64_IMM:
            emit_alu64_imm8(state, 0xc1, 4, dst, inst.imm);
            break;
        case EBPF_OP_LSH64_REG:
            emit_mov(state, src, RCX);
            emit_alu64(state, 0xd3, 4, dst);
            break;
        case EBPF_OP_RSH64_IMM:
            emit_alu64_imm8(state, 0xc1, 5, dst, inst.imm);
            break;
        case EBPF_OP_RSH64_REG:
            emit_mov(state, src, RCX);
            emit_alu64(state, 0xd3, 5, dst);
            break;
        case EBPF_OP_NEG64:
            emit_alu64(state, 0xf7, 3, dst);
            break;
        case EBPF_OP_XOR64_IMM:
            emit_alu64_imm32(state, 0x81, 6, dst, inst.imm);
            break;
        case EBPF_OP_XOR64_REG:
            emit_alu64(state, 0x31, src, dst);
            break;
        case EBPF_OP_MOV64_IMM:
            emit_load_imm(state, dst, inst.imm);
            break;
        case EBPF_OP_MOV64_REG:
            emit_mov(state, src, dst);
            break;
        case EBPF_OP_ARSH64_IMM:
            emit_alu64_imm8(state, 0xc1, 7, dst, inst.imm);
            break;
        case EBPF_OP_ARSH64_REG:
            emit_mov(state, src, RCX);
            emit_alu64(state, 0xd3, 7, dst);
            break;

        /* TODO use 8 bit immediate when possible */
        case EBPF_OP_JA:
            emit_jmp(state, target_pc);
            break;
        case EBPF_OP_JEQ_IMM:
        /* case EBPF_OP_JEQ32_IMM: */
            emit_cmp_imm32(state, dst, inst.imm);
            emit_jcc(state, 0x84, target_pc);
            break;
        case EBPF_OP_JEQ_REG:
        /* case EBPF_OP_JEQ32_REG: */
            emit_cmp(state, src, dst);
            emit_jcc(state, 0x84, target_pc);
            break;
        case EBPF_OP_JGT_IMM:
        /* case EBPF_OP_JGT32_IMM: */
            emit_cmp_imm32(state, dst, inst.imm);
            emit_jcc(state, 0x87, target_pc);
            break;
        case EBPF_OP_JGT_REG:
        /* case EBPF_OP_JGT32_REG: */
            emit_cmp(state, src, dst);
            emit_jcc(state, 0x87, target_pc);
            break;
        case EBPF_OP_JGE_IMM:
        /* case EBPF_OP_JGE32_IMM: */
            emit_cmp_imm32(state, dst, inst.imm);
            emit_jcc(state, 0x83, target_pc);
            break;
        case EBPF_OP_JGE_REG:
        /* case EBPF_OP_JGE32_REG: */
            emit_cmp(state, src, dst);
            emit_jcc(state, 0x83, target_pc);
            break;
        case EBPF_OP_JLT_IMM:
        /* case EBPF_OP_JLT32_IMM: */
            emit_cmp_imm32(state, dst, inst.imm);
            emit_jcc(state, 0x82, target_pc);
            break;
        case EBPF_OP_JLT_REG:
        /* case EBPF_OP_JLT32_REG: */
            emit_cmp(state, src, dst);
            emit_jcc(state, 0x82, target_pc);
            break;
        case EBPF_OP_JLE_IMM:
        /* case EBPF_OP_JLE32_IMM: */
            emit_cmp_imm32(state, dst, inst.imm);
            emit_jcc(state, 0x86, target_pc);
            break;
        case EBPF_OP_JLE_REG:
        /* case EBPF_OP_JLE32_REG: */
            emit_cmp(state, src, dst);
            emit_jcc(state, 0x86, target_pc);
            break;
        case EBPF_OP_JSET_IMM:
        /* case EBPF_OP_JSET32_IMM: */
            emit_alu64_imm32(state, 0xf7, 0, dst, inst.imm);
            emit_jcc(state, 0x85, target_pc);
            break;
        case EBPF_OP_JSET_REG:
        /* case EBPF_OP_JSET32_REG: */
            emit_alu64(state, 0x85, src, dst);
            emit_jcc(state, 0x85, target_pc);
            break;
        case EBPF_OP_JNE_IMM:
        /* case EBPF_OP_JNE32_IMM: */
            emit_cmp_imm32(state, dst, inst.imm);
            emit_jcc(state, 0x85, target_pc);
            break;
        case EBPF_OP_JNE_REG:
        /* case EBPF_OP_JNE32_REG: */
            emit_cmp(state, src, dst);
            emit_jcc(state, 0x85, target_pc);
            break;
        case EBPF_OP_JSGT_IMM:
        /* case EBPF_OP_JSGT32_IMM: */
            emit_cmp_imm32(state, dst, inst.imm);
            emit_jcc(state, 0x8f, target_pc);
            break;
        case EBPF_OP_JSGT_REG:
        /* case EBPF_OP_JSGT32_REG: */
            emit_cmp(state, src, dst);
            emit_jcc(state, 0x8f, target_pc);
            break;
        case EBPF_OP_JSGE_IMM:
        /* case EBPF_OP_JSGE32_IMM: */
            emit_cmp_imm32(state, dst, inst.imm);
            emit_jcc(state, 0x8d, target_pc);
            break;
        case EBPF_OP_JSGE_REG:
        /* case EBPF_OP_JSGE32_REG: */
            emit_cmp(state, src, dst);
            emit_jcc(state, 0x8d, target_pc);
            break;
        case EBPF_OP_JSLT_IMM:
        /* case EBPF_OP_JSLT32_IMM: */
            emit_cmp_imm32(state, dst, inst.imm);
            emit_jcc(state, 0x8c, target_pc);
            break;
        case EBPF_OP_JSLT_REG:
        /* case EBPF_OP_JSLT32_REG: */
            emit_cmp(state, src, dst);
            emit_jcc(state, 0x8c, target_pc);
            break;
        case EBPF_OP_JSLE_IMM:
        /* case EBPF_OP_JSLE32_IMM: */
            emit_cmp_imm32(state, dst, inst.imm);
            emit_jcc(state, 0x8e, target_pc);
            break;
        case EBPF_OP_JSLE_REG:
        /* case EBPF_OP_JSLE32_REG: */
            emit_cmp(state, src, dst);
            emit_jcc(state, 0x8e, target_pc);
            break;
        case EBPF_OP_CALL:
            if (inst.imm == UBPF_PREFETCH_HELPER) {
                emit2(state, 0x180F);
                emit_modrm(state, 0, 1, map_register(1));
                /* printf("encoding prefetch!"); */
                break;
            }
            /* We reserve RCX for shifts */
            emit_mov(state, RCX_ALT, RCX);
            emit_call(state, vm->ext_funcs[inst.imm]);
            if (inst.imm == vm->unwind_stack_extension_index) {
                emit_cmp_imm32(state, map_register(0), 0);
                emit_jcc(state, 0x84, TARGET_PC_EXIT);
            }
            break;
        case EBPF_OP_EXIT:
            if (i != num_insts - 1) {
                emit_jmp(state, TARGET_PC_EXIT);
            }
            break;

        /* JMP32 */
        case EBPF_OP_JEQ32_IMM:
            emit_cmp32_imm32(state, dst, inst.imm);
            emit_jcc(state, 0x84, target_pc);
            break;
        case EBPF_OP_JEQ32_REG:
            emit_cmp32(state, src, dst);
            emit_jcc(state, 0x84, target_pc);
            break;
        case EBPF_OP_JGT32_IMM:
            emit_cmp32_imm32(state, dst, inst.imm);
            emit_jcc(state, 0x87, target_pc);
            break;
        case EBPF_OP_JGT32_REG:
            emit_cmp32(state, src, dst);
            emit_jcc(state, 0x87, target_pc);
            break;
        case EBPF_OP_JGE32_IMM:
            emit_cmp32_imm32(state, dst, inst.imm);
            emit_jcc(state, 0x83, target_pc);
            break;
        case EBPF_OP_JGE32_REG:
            emit_cmp32(state, src, dst);
            emit_jcc(state, 0x83, target_pc);
            break;
        case EBPF_OP_JLT32_IMM:
            emit_cmp32_imm32(state, dst, inst.imm);
            emit_jcc(state, 0x82, target_pc);
            break;
        case EBPF_OP_JLT32_REG:
            emit_cmp32(state, src, dst);
            emit_jcc(state, 0x82, target_pc);
            break;
        case EBPF_OP_JLE32_IMM:
            emit_cmp32_imm32(state, dst, inst.imm);
            emit_jcc(state, 0x86, target_pc);
            break;
        case EBPF_OP_JLE32_REG:
            emit_cmp32(state, src, dst);
            emit_jcc(state, 0x86, target_pc);
            break;
        case EBPF_OP_JSET32_IMM:
            emit_alu32_imm32(state, 0xf7, 0, dst, inst.imm);
            emit_jcc(state, 0x85, target_pc);
            break;
        case EBPF_OP_JSET32_REG:
            emit_alu32(state, 0x85, src, dst);
            emit_jcc(state, 0x85, target_pc);
            break;
        case EBPF_OP_JNE32_IMM:
            emit_cmp32_imm32(state, dst, inst.imm);
            emit_jcc(state, 0x85, target_pc);
            break;
        case EBPF_OP_JNE32_REG:
            emit_cmp32(state, src, dst);
            emit_jcc(state, 0x85, target_pc);
            break;
        case EBPF_OP_JSGT32_IMM:
            emit_cmp32_imm32(state, dst, inst.imm);
            emit_jcc(state, 0x8f, target_pc);
            break;
        case EBPF_OP_JSGT32_REG:
            emit_cmp32(state, src, dst);
            emit_jcc(state, 0x8f, target_pc);
            break;
        case EBPF_OP_JSGE32_IMM:
            emit_cmp32_imm32(state, dst, inst.imm);
            emit_jcc(state, 0x8d, target_pc);
            break;
        case EBPF_OP_JSGE32_REG:
            emit_cmp32(state, src, dst);
            emit_jcc(state, 0x8d, target_pc);
            break;
        case EBPF_OP_JSLT32_IMM:
            emit_cmp32_imm32(state, dst, inst.imm);
            emit_jcc(state, 0x8c, target_pc);
            break;
        case EBPF_OP_JSLT32_REG:
            emit_cmp32(state, src, dst);
            emit_jcc(state, 0x8c, target_pc);
            break;
        case EBPF_OP_JSLE32_IMM:
            emit_cmp32_imm32(state, dst, inst.imm);
            emit_jcc(state, 0x8e, target_pc);
            break;
        case EBPF_OP_JSLE32_REG:
            emit_cmp32(state, src, dst);
            emit_jcc(state, 0x8e, target_pc);
            break;
        /* ABS or IND load (Oko) */
        case EBPF_OP_LDABSB:
            emit_load(state, S8,  R10, RAX, inst.imm);
            break;
        case EBPF_OP_LDABSH:
            emit_load(state, S16, R10, RAX, inst.imm);
            break;
        case EBPF_OP_LDABSW:
            emit_load(state, S32, R10, RAX, inst.imm);
            break;
        case EBPF_OP_LDABSDW:
            emit_load(state, S64, R10, RAX, inst.imm);
            break;
        case EBPF_OP_LDINDB:
            emit_mov(state, R10, R11);
            emit_alu64(state, 0x01, src, R11);
            emit_load(state, S8,  R11, RAX, inst.imm);
            break;
        case EBPF_OP_LDINDH:
            emit_mov(state, R10, R11);
            emit_alu64(state, 0x01, src, R11);
            emit_load(state, S16, R11, RAX, inst.imm);
            break;
        case EBPF_OP_LDINDW:
            emit_mov(state, R10, R11);
            emit_alu64(state, 0x01, src, R11);
            emit_load(state, S32, R11, RAX, inst.imm);
            break;
        case EBPF_OP_LDINDDW:
            emit_mov(state, R10, R11);
            emit_alu64(state, 0x01, src, R11);
            emit_load(state, S64, R11, RAX, inst.imm);
            break;

        case EBPF_OP_LDXW:
            emit_load(state, S32, src, dst, inst.offset);
            break;
        case EBPF_OP_LDXH:
            emit_load(state, S16, src, dst, inst.offset);
            break;
        case EBPF_OP_LDXB:
            emit_load(state, S8, src, dst, inst.offset);
            break;
        case EBPF_OP_LDXDW:
            emit_load(state, S64, src, dst, inst.offset);
            break;

        case EBPF_OP_STW:
            emit_store_imm32(state, S32, dst, inst.offset, inst.imm);
            break;
        case EBPF_OP_STH:
            emit_store_imm32(state, S16, dst, inst.offset, inst.imm);
            break;
        case EBPF_OP_STB:
            emit_store_imm32(state, S8, dst, inst.offset, inst.imm);
            break;
        case EBPF_OP_STDW:
            emit_store_imm32(state, S64, dst, inst.offset, inst.imm);
            break;

        case EBPF_OP_STXW:
            emit_store(state, S32, src, dst, inst.offset);
            break;
        case EBPF_OP_STXH:
            emit_store(state, S16, src, dst, inst.offset);
            break;
        case EBPF_OP_STXB:
            emit_store(state, S8, src, dst, inst.offset);
            break;
        case EBPF_OP_STXDW:
            emit_store(state, S64, src, dst, inst.offset);
            break;

        case EBPF_OP_LDDW: {
            struct ebpf_inst inst2 = insts[++i];
            uint64_t imm = (uint32_t)inst.imm | ((uint64_t)inst2.imm << 32);
            emit_load_imm(state, dst, imm);
            break;
        }

        /* Atomic Operation  */
        case EBPF_OP_AT_4:
            emit_atomic(state, S32, src, dst, inst.offset, inst.imm);
            break;
        case EBPF_OP_AT_8:
            emit_atomic(state, S64, src, dst, inst.offset, inst.imm);
            break;

        default:
            *errmsg = ubpf_error("Unknown instruction at PC %d: opcode %02x", i, inst.opcode);
            return -1;
        }
    }

    /* Epilogue */
    state->exit_loc = state->offset;

    /* Move register 0 into rax */
    if (map_register(0) != RAX) {
        emit_mov(state, map_register(0), RAX);
    }

    /* Deallocate stack space */
    emit_alu64_imm32(state, 0x81, 0, RSP, UBPF_STACK_SIZE);

    /* Restore platform non-volatile registers */
    for (i = 0; i < _countof(platform_nonvolatile_registers); i++)
    {
        emit_pop(state, platform_nonvolatile_registers[_countof(platform_nonvolatile_registers) - i - 1]);
    }

    emit1(state, 0xc3); /* ret */

    /* Division by zero handler */
    state->div_by_zero_loc = state->offset;
    const char *div_by_zero_fmt = "uBPF error: division by zero at PC %u\n";
    // RCX is the first parameter register for Windows, so first save the value.
    emit_mov(state, RCX, platform_parameter_registers[2]); /* muldivmod stored pc in RCX */
    emit_load_imm(state, platform_parameter_registers[0], (uintptr_t)stderr);
    emit_load_imm(state, platform_parameter_registers[1], (uintptr_t)div_by_zero_fmt);
    emit_call(state, vm->error_printf);

    emit_load_imm(state, map_register(0), -1);
    emit_jmp(state, TARGET_PC_EXIT);

    return 0;
}

static void
muldivmod(struct jit_state *state, uint16_t pc, uint8_t opcode, int src, int dst, int32_t imm)
{
    bool mul = (opcode & EBPF_ALU_OP_MASK) == (EBPF_OP_MUL_IMM & EBPF_ALU_OP_MASK);
    bool div = (opcode & EBPF_ALU_OP_MASK) == (EBPF_OP_DIV_IMM & EBPF_ALU_OP_MASK);
    bool mod = (opcode & EBPF_ALU_OP_MASK) == (EBPF_OP_MOD_IMM & EBPF_ALU_OP_MASK);
    bool is64 = (opcode & EBPF_CLS_MASK) == EBPF_CLS_ALU64;

    if (div || mod) {
        emit_load_imm(state, RCX, pc);

        /* test src,src */
        if (is64) {
            emit_alu64(state, 0x85, src, src);
        } else {
            emit_alu32(state, 0x85, src, src);
        }

        /* jz div_by_zero */
        emit_jcc(state, 0x84, TARGET_PC_DIV_BY_ZERO);
    }

    if (dst != RAX) {
        emit_push(state, RAX);
    }
    if (dst != RDX) {
        emit_push(state, RDX);
    }
    if (imm) {
        emit_load_imm(state, RCX, imm);
    } else {
        emit_mov(state, src, RCX);
    }

    emit_mov(state, dst, RAX);

    if (div || mod) {
        /* xor %edx,%edx */
        emit_alu32(state, 0x31, RDX, RDX);
    }

    if (is64) {
        emit_rex(state, 1, 0, 0, 0);
    }

    /* mul %ecx or div %ecx */
    emit_alu32(state, 0xf7, mul ? 4 : 6, RCX);

    if (dst != RDX) {
        if (mod) {
            emit_mov(state, RDX, dst);
        }
        emit_pop(state, RDX);
    }
    if (dst != RAX) {
        if (div || mul) {
            emit_mov(state, RAX, dst);
        }
        emit_pop(state, RAX);
    }
}

static void
resolve_jumps(struct jit_state *state)
{
    int i;
    for (i = 0; i < state->num_jumps; i++) {
        struct jump jump = state->jumps[i];

        int target_loc;
        if (jump.target_pc == TARGET_PC_EXIT) {
            target_loc = state->exit_loc;
        } else if (jump.target_pc == TARGET_PC_DIV_BY_ZERO) {
            target_loc = state->div_by_zero_loc;
        } else {
            target_loc = state->pc_locs[jump.target_pc];
        }

        /* Assumes jump offset is at end of instruction */
        uint32_t rel = target_loc - (jump.offset_loc + sizeof(uint32_t));

        uint8_t *offset_ptr = &state->buf[jump.offset_loc];
        memcpy(offset_ptr, &rel, sizeof(uint32_t));
    }
}

int
ubpf_translate(struct ubpf_vm *vm, uint8_t * buffer, size_t * size, char **errmsg)
{
    struct jit_state state;
    int result = -1;

    state.offset = 0;
    state.size = *size;
    state.buf = buffer;
    state.pc_locs = calloc(UBPF_MAX_INSTS+1, sizeof(state.pc_locs[0]));
    state.jumps = calloc(UBPF_MAX_INSTS, sizeof(state.jumps[0]));
    state.num_jumps = 0;

    if (translate(vm, &state, vm->insts[0], vm->num_insts[0], errmsg) < 0) {
        goto out;
    }

    resolve_jumps(&state);
    result = 0;

    *size = state.offset;

out:
    free(state.pc_locs);
    free(state.jumps);
    return result;
}

static int
ubpf_translate_prog(struct ubpf_vm *vm, uint8_t * buffer, size_t * size,
        uint32_t prog_index, char **errmsg)
{
    struct jit_state state;
    int result = -1;

    state.offset = 0;
    state.size = *size;
    state.buf = buffer;
    state.pc_locs = calloc(UBPF_MAX_INSTS+1, sizeof(state.pc_locs[0]));
    state.jumps = calloc(UBPF_MAX_INSTS, sizeof(state.jumps[0]));
    state.num_jumps = 0;

    struct ebpf_inst *insts = vm->insts[prog_index];
    uint32_t num_insts = vm->num_insts[prog_index];
    if (translate(vm, &state, insts, num_insts, errmsg) < 0) {
        goto out;
    }

    resolve_jumps(&state);
    result = 0;

    *size = state.offset;

out:
    free(state.pc_locs);
    free(state.jumps);
    return result;
}

ubpf_jit_fn
ubpf_compile(struct ubpf_vm *vm, uint32_t prog_index, char **errmsg)
{
    void *jitted = NULL;
    uint8_t *buffer = NULL;
    size_t jitted_size;
    int page_size;

    if (prog_index >= vm->sz_yield_chain) {
        *errmsg = ubpf_error("code has not been loaded into this VM");
        return NULL;
    }

    if (vm->jitted[prog_index]) {
        /* already compiled this prog */
        return vm->jitted[prog_index];
    }

    *errmsg = NULL;

    if (!vm->insts || !vm->insts[prog_index]) {
        *errmsg = ubpf_error("code has not been loaded into this VM (%p, %p)", vm->insts, vm->insts[0]);
        return NULL;
    }

    jitted_size = 65536;
    buffer = calloc(jitted_size, 1);

    if (ubpf_translate_prog(vm, buffer, &jitted_size, prog_index, errmsg) < 0) {
        goto out;
    }

    /* int fd = gen_elf_file_for_jit_code(buffer, jitted_size, prog_index); */
    int fd = -1; /* Do not generate the ELF file it is not very useful without DWARF */
    void * const page_addr = _UBPF_PROG_ADDR(prog_index);

    /* First try to use a HUGE page for the program (there is no point in doing
     * this) */
    /* page_size = 1 << 30; */
    /* jitted = mmap(0, jitted_size, */
    /*         PROT_READ | PROT_WRITE, */
    /*         MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, -1, 0); */

    page_size = jitted_size;
    if (fd >= 0) {
        /* /1* NOTE: this path is WIP and is not implemented yet! *1/ */
        /* goto out; */
        uint8_t *tmp = mmap(page_addr, jitted_size,
                PROT_READ | PROT_EXEC, MAP_PRIVATE | MAP_FIXED_NOREPLACE, fd, 0);
        // Either it si mapped or not. We do not need the descriptor any how.
        close(fd);
        if (tmp == MAP_FAILED) {
            *errmsg = ubpf_error("Failed to map the file (fd: %d) (%s) [target addr: %p]\n", fd, strerror(errno), page_addr);
            goto out;
        }
        Elf64_Ehdr *ehdr = (Elf64_Ehdr *)tmp;
        Elf64_Phdr* phdr = (Elf64_Phdr*)(tmp + ehdr->e_phoff);
        assert(ehdr->e_phnum >= 1);
        assert((phdr->p_type & PT_LOAD) != 0);
        /* printf("phnum: %d\n",ehdr->e_phnum); */
        /* printf("phoff: %ld\n",ehdr->e_phoff); */

        // TODO:  Fix this with proper code that goes through the sections and
        // find the right one
        const Elf64_Shdr *shdr = (void *)tmp + ehdr->e_shoff + (1 * ehdr->e_shentsize);
        /* printf("%ld ?= %ld\n", shdr->sh_size, jitted_size); */
        assert(shdr->sh_size == jitted_size);
        size_t prog_off = shdr->sh_offset;
        /* printf("prog offset: %ld\n", phdr[0].p_offset); */
        tmp += prog_off;
        for (int i = 0; i < jitted_size; i++) {
            /* printf("%d: %x \t %x\n", i, tmp[i], buffer[i]); */
            if(tmp[i] != buffer[i]) {
                printf("Error: file page did not matched the code!\n");
                goto out;
            }
        }
        jitted = tmp;
        printf("ubpf: ELF mapped: Every byte matches (%lu)\n", jitted_size);
    } else {
        // Original path, we have the code; allocate a memory page and copy it
        // there. Set executable flag later.
        jitted = mmap(page_addr, jitted_size, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
        if (jitted == MAP_FAILED) {
            if (jitted == MAP_FAILED) {
                *errmsg = ubpf_error("internal uBPF error: mmap failed: %s\n",
                        strerror(errno));
                goto out;
            }
        }

        memcpy(jitted, buffer, jitted_size);
        if (mprotect(jitted, page_size, PROT_READ | PROT_EXEC) < 0) {
            *errmsg = ubpf_error("internal uBPF error: mprotect failed: %s\n",
                    strerror(errno));
            goto out;
        }
    }

    vm->jitted[prog_index] = jitted;
    vm->jitted_size[prog_index] = jitted_size;

out:
    free(buffer);
    if (jitted && vm->jitted[prog_index] == NULL) {
        munmap(jitted, jitted_size);
    }
    report_perf_map(vm, prog_index);
    return vm->jitted[prog_index];
}

uint8_t *
ubpf_dump_jitted_fn(struct ubpf_vm *vm, unsigned int *size)
{
    *size = vm->jitted_size[0];
    return (uint8_t *)vm->jitted[0];
}
