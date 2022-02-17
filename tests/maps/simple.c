/* Add some definitions which should probably be part of ubpf.h */
enum bpf_map_type {
    BPF_MAP_TYPE_ARRAY = 1,
    BPF_MAP_TYPE_BLOOMFILTER = 2,
    BPF_MAP_TYPE_COUNTMIN = 3,
    BPF_MAP_TYPE_HASHMAP = 4,
};

struct bpf_map_def {
    enum bpf_map_type type;
    unsigned int key_size;
    unsigned int value_size;
    unsigned int max_entries;
    unsigned int nb_hash_functions;
};

struct bpf_map_def reg = {
    .type = BPF_MAP_TYPE_HASHMAP,
    .key_size = sizeof(int),
    .value_size = sizeof(long long int),
    .max_entries = 100,
    .nb_hash_functions = 0,
};

int bpf_prog(void *pkt) {
	return 0x367;
}
