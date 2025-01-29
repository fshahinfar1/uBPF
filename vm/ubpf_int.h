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

#ifndef UBPF_INT_H
#define UBPF_INT_H

#include "inc/ubpf.h"
#include "ebpf.h"

struct ebpf_inst;
typedef uint64_t (*ext_func)(uint64_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4);

char *ubpf_error(const char *fmt, ...);
unsigned int ubpf_lookup_registered_function(struct ubpf_vm *vm, const char *name);
int ubpf_load_prog(struct ubpf_vm *vm, const void *code, uint32_t code_len, uint16_t prog_index, char **errmsg);

/* Note: These codes are Add from Oko project */
/* #define MAX_INSTS 65536 */
/* #define STACK_SIZE 512 */
#define NB_FUNC_ARGS 5

#define MAX_YIELD_CHAIN_FUNCS 8

struct ubpf_map_ops {
    unsigned int (*map_size)(const struct ubpf_map *map);
    unsigned int (*map_dump)(const struct ubpf_map *map, void *data);
    void *(*map_lookup)(const struct ubpf_map *map, const void *key);
    int (*map_update)(struct ubpf_map *map, const void *key, void *value);
    int (*map_delete)(struct ubpf_map *map, const void *key);
    int (*map_add)(struct ubpf_map *map, void *value);

    void (*map_lookup_p1)(const struct ubpf_map *map, const void *key /* input */);
    void *(*map_lookup_p2)(const struct ubpf_map *map, void *key /* output */);
};

struct ubpf_map {
    enum ubpf_map_type type;
    struct ubpf_map_ops ops;
    unsigned int key_size;
    unsigned int value_size;
    unsigned int max_entries;
    void *data;
};

enum ubpf_reg_type {
    UNINIT        = 0,
    UNKNOWN       = 1,
    NULL_VALUE    = 2,
    IMM           = 4,
    MAP_PTR       = 8,
    MAP_VALUE_PTR = 16,
    PKT_PTR       = 32,
    PKT_SIZE      = 64,
    STACK_PTR     = 128,
};

enum ubpf_arg_size {
    SIZE_64 = 0,
    SIZE_MAP_KEY,
    SIZE_MAP_VALUE,
    SIZE_PTR_MAX,
};

struct ubpf_func_proto {
    ext_func func;
    enum ubpf_reg_type arg_types[NB_FUNC_ARGS];
    enum ubpf_arg_size arg_sizes[NB_FUNC_ARGS];
    enum ubpf_reg_type ret;
};

// TODO: Oko has some fields specially for ext_funcs that I am not using now.
// struct ubpf_vm {
//     ovs_be16 filter_prog;
//     struct hmap_node hmap_node;
//     struct ebpf_inst *insts;
//     uint16_t num_insts;
//     ubpf_jit_fn jitted;
//     size_t jitted_size;
//     struct ubpf_func_proto *ext_funcs;
//     const char **ext_func_names;
//     struct ubpf_map **ext_maps;
//     const char **ext_map_names;
//     uint16_t nb_maps;
// };

struct ubpf_map *ubpf_lookup_registered_map(struct ubpf_vm *vm, const char *name);
/* ----------------------------- */

struct ubpf_vm {
    uint16_t sz_yield_chain;
    struct ebpf_inst **insts;
    uint16_t *num_insts;
    ubpf_jit_fn *jitted;
    size_t *jitted_size;
    ext_func *ext_funcs;
    const char **ext_func_names;
    /* inline_func *ext_func_inline_funcs; */
    bool bounds_check_enabled;
    int (*error_printf)(FILE* stream, const char* format, ...);
    int unwind_stack_extension_index;
    struct ubpf_map **ext_maps;
    const char **ext_map_names;
    uint16_t nb_maps;
};

/* Handling state for a batch of packets. Used to implement two phase lookup. */
#define MAX_BATCH_SZ 128
extern int offset_in_batch;
typedef struct {
    uint32_t p1_flag;
    uint32_t hash;
    void *head;
} yield_state_t;
extern yield_state_t yield_state[MAX_BATCH_SZ];

#endif
