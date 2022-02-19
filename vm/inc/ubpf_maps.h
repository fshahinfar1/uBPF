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
#endif
