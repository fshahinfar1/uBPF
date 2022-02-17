#ifndef UBPF_MAPS_H
#define UBPF_MAPS_H

/* These should be available to ebpf programs that
 * are trying to use userspace maps */
enum ubpf_map_type {
    UBPF_MAP_TYPE_ARRAY = 1,
    UBPF_MAP_TYPE_BLOOMFILTER = 2,
    UBPF_MAP_TYPE_COUNTMIN = 3,
    UBPF_MAP_TYPE_HASHMAP = 4,
};

struct ubpf_map_def {
    enum ubpf_map_type type;
    unsigned int key_size;
    unsigned int value_size;
    unsigned int max_entries;
    unsigned int nb_hash_functions;
};
/* ------------------------ */

struct ubpf_map;

struct ubpf_map_ops {
    unsigned int (*map_size)(const struct ubpf_map *map);
    unsigned int (*map_dump)(const struct ubpf_map *map, void *data);
    void *(*map_lookup)(const struct ubpf_map *map, const void *key);
    int (*map_update)(struct ubpf_map *map, const void *key, void *value);
    int (*map_delete)(struct ubpf_map *map, const void *key);
    int (*map_add)(struct ubpf_map *map, void *value);
};

struct ubpf_map {
    enum ubpf_map_type type;
    struct ubpf_map_ops ops;
    unsigned int key_size;
    unsigned int value_size;
    unsigned int max_entries;
    void *data;
};
#endif
