/*
 * Copyright 2018 Orange
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
#ifndef UBPF_ARRAY_H
#define UBPF_ARRAY_H 1
#include <stdio.h>
#include <string.h>

#include "../ubpf_int.h"

void *ubpf_array_create(const struct ubpf_map_def *map_def);
void *ubpf_array_lookup(const struct ubpf_map *map, const void *key);
int ubpf_array_update(struct ubpf_map *map, const void *key, void *value);

void *
ubpf_array_create(const struct ubpf_map_def *map_def)
{
    return calloc(map_def->max_entries, map_def->value_size);
}

void *
ubpf_array_lookup(const struct ubpf_map *map, const void *key)
{
    uint64_t idx = *((const uint32_t *)key);
    if (idx >= map->max_entries) {
        /* printf("size: %d idx: %d\n", map->max_entries, idx); */
        return NULL;
    }
    return (void *)((uint64_t)map->data + idx * map->value_size);
}

int
ubpf_array_update(struct ubpf_map *map, const void *key, void *value)
{
    uint64_t idx = *((const uint32_t *)key);
    if (idx >= map->max_entries) {
        return -5;
    }
    void *addr = (void *)((uint64_t)map->data + map->value_size * idx);
    memcpy(addr, value, map->value_size);
    return 0;
}

static const struct ubpf_map_ops ubpf_array_ops = {
    .map_lookup = ubpf_array_lookup,
    .map_update = ubpf_array_update,
    .map_delete = NULL,
    .map_add = NULL,
    .map_size = NULL,
    .map_dump = NULL,
};

#endif
