
#include <sys/types.h>
#include <stdint.h>

struct st_kallsyms {
    unsigned long base;
    const void *data;
    size_t size;
    unsigned long *kallsyms_addresses;
    unsigned long kallsyms_num_syms;
    uint8_t *kallsyms_names;
    unsigned long *kallsyms_markers;
    uint8_t *kallsyms_token_table;
    uint16_t *kallsyms_token_index;
    int has_type_tbl;
};

typedef struct st_kallsyms kallsyms_t;

int kallsyms_init(kallsyms_t *, const void *, size_t);
unsigned long kallsyms_lookup(kallsyms_t *, const char *);
void kallsyms_foreach(kallsyms_t *, int (*)(void *, const char *, long *), void *);
void kallsyms_free(kallsyms_t *);

