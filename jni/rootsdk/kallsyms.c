
#include "log.h"
#include "kallsyms.h"

#define KSYM_NAME_LEN 128

typedef uint8_t u8;
typedef uint16_t u16;

/*
 * Expand a compressed symbol data into the resulting uncompressed string,
 * given the offset to where the symbol is in the compressed stream.
 */
static unsigned int kallsyms_expand_symbol(kallsyms_t *ctx, unsigned int off, char *result)
{
	int len, skipped_first = 0;
	const u8 *tptr, *data;

	/* Get the compressed symbol length from the first symbol byte. */
	data = &ctx->kallsyms_names[off];
	len = *data;
	data++;

	/*
	 * Update the offset to return the offset for the next symbol on
	 * the compressed stream.
	 */
	off += len + 1;

	/*
	 * For every byte on the compressed symbol data, copy the table
	 * entry for that byte.
	 */
	while (len) {
		tptr = &ctx->kallsyms_token_table[ctx->kallsyms_token_index[*data]];
		data++;
		len--;

		while (*tptr) {
			if (skipped_first) {
				*result = *tptr;
				result++;
			} else
				skipped_first = 1;
			tptr++;
		}
	}

	*result = '\0';

	/* Return to offset to the next symbol. */
	return off;
}

/*
 * Find the offset on the compressed stream given and index in the
 * kallsyms array.
 */
static unsigned int get_symbol_offset(kallsyms_t *ctx, unsigned long pos)
{
	const u8 *name;
	int i;

	/*
	 * Use the closest marker we have. We have markers every 256 positions,
	 * so that should be close enough.
	 */
	name = &ctx->kallsyms_names[ctx->kallsyms_markers[pos >> 8]];

	/*
	 * Sequentially scan all the symbols up to the point we're searching
	 * for. Every symbol is stored in a [<len>][<len> bytes of data] format,
	 * so we just need to add the len to the current pointer for every
	 * symbol we wish to skip.
	 */
	for (i = 0; i < (pos & 0xFF); i++)
		name = name + (*name) + 1;

	return name - ctx->kallsyms_names;
}

static unsigned long kallsyms_table_start1[] = {
    0xc0008000, 0xc0008000, 0xc0008000, 0xc0008000
};

static unsigned long kallsyms_table_start2[] = {
    0xc00081c0, 0xc00081c0, 0xc00081c0
};

static unsigned long kallsyms_table_start3[] = {
    0xc0008180, 0xc0008180, 0xc0008180
};

static unsigned long kallsyms_table_start_marks[] = {
    (unsigned long) kallsyms_table_start1, sizeof(kallsyms_table_start1),
    (unsigned long) kallsyms_table_start2, sizeof(kallsyms_table_start2),
    (unsigned long) kallsyms_table_start3, sizeof(kallsyms_table_start3),
};

static int has_type_tbl(const void *data, size_t size) {
    int i;

    if (size < 256 * 4)
        return 0;
    for (i = 0; i < 256; i++) {
        unsigned long x = *((const unsigned long *) data + i) & ~0x20202020;
        if (x != 0x54545454)
            return 0;
    }

    return -1;
}

int kallsyms_init(kallsyms_t *ctx, const void *data, size_t size) {
    int err, i, n, off;
    void *test;
    unsigned long *p, *end;

    ctx->data = data;
    ctx->size = size;
    ctx->has_type_tbl = 0;
    for (i = 0; i < sizeof(kallsyms_table_start_marks) / (2 * sizeof(long)); i++) {
        err = 0;
        end = (unsigned long *)((char *) data + size);
        /* guess kallsyms_addresses */
        test = memmem(data, size,
            (void *) kallsyms_table_start_marks[i * 2], kallsyms_table_start_marks[i * 2 + 1]);
        if (!test) {
            LOGD("start not match");
            err = -1;
            continue;
        }
        ctx->kallsyms_addresses = (unsigned long *) test;
        /* guess start of kallsyms_num_syms */
        n = 0;
        p = (unsigned long *) ctx->kallsyms_addresses;
        while (*p) {
            n++;
            p++;
            if (p >= end) {
                LOGD("exceeded");
                err = -1;
                break;
            }
        }
        if (err)
            continue;
        // skip zeroes
        while (*p == 0) {
            p++;
            if (p >= end) {
                LOGD("exceeded");
                err = -1;
                break;
            }
        }
        if (err)
            continue;
        if (n != *p) {
            LOGV("kallsyms_num_syms not match, guessed %d, actual %d.", (int) n, (int) *p);
            continue;
        }
        ctx->kallsyms_num_syms = n;
        LOGV("kallsyms_num_syms = %d.", (int) ctx->kallsyms_num_syms);
        // skip zeroes
        while (*p == 0) {
            p++;
            if (p >= end) {
                err = -1;
                break;
            }
        }
        if (err)
            continue;
        /* guess start of kallsyms_names */
        ctx->kallsyms_names = (uint8_t *) p;
        off = 0;
        for (i = 0; i < n; i++) {
            off += p[i];
            off += 1;
            if (((char *) p + off) >= (char *) end) {
                err = -1;
                break;
            }
        }
        if (err || (i != n))
            continue;
        p = (unsigned long *)((char *) p + off - 1);
        // .align 2
        if ((unsigned long) p & 3)
            p = (unsigned long *)((((unsigned long) p) | 3) + 1);
        if (p >= end) {
            err = -1;
            continue;
        }
        // skip zeroes
        while (*p == 0) {
            p++;
            if (p >= end) {
                err = -1;
                break;
            }
        }
        /* skip symbol type table */
        if (has_type_tbl(p, end - p)) {
            ctx->has_type_tbl = -1;
            while (*p != 0) {
                p++;
                if (p >= end) {
                    err = -1;
                    break;
                }
            }
            if (err)
                continue;
        }
        // skip zeroes
        while (*p == 0) {
            p++;
            if (p >= end) {
                err = -1;
                break;
            }
        }
        /* guess kallsyms_markers */
        p--;
        ctx->kallsyms_markers = p;
        p += (((ctx->kallsyms_num_syms - 1) >> 8) + 1);
        if (p >= end) {
            err = -1;
            continue;
        }
        // skip zeroes
        while (*p == 0) {
            p++;
            if (p >= end) {
                err = -1;
                break;
            }
        }
        /* guess kallsyms_token_table */
        ctx->kallsyms_token_table = (uint8_t *) p;
        i = 0;
        while (ctx->kallsyms_token_table[i] || ctx->kallsyms_token_table[i + 1]) {
            i++;
            if (ctx->kallsyms_token_table + i - 1 >= (uint8_t *) end) {
                err = -1;
                break;
            }
        }
        if (err)
            continue;
        while (ctx->kallsyms_token_table[i] == 0) {
            i++;
            if (ctx->kallsyms_token_table + i - 1 >= (uint8_t *) end) {
                err = -1;
                break;
            }
        }
        if (err)
            continue;
        /* guess kallsyms_token_index */
        ctx->kallsyms_token_index = (uint16_t *)(ctx->kallsyms_token_table + i - 2);

        return 0;
    }
    return -1;
}


/* Lookup the address for this symbol. Returns 0 if not found. */
unsigned long kallsyms_lookup(kallsyms_t *ctx, const char *name)
{
	char namebuf[KSYM_NAME_LEN];
	unsigned long i;
	unsigned int off;

	for (i = 0, off = 0; i < ctx->kallsyms_num_syms; i++) {
		off = kallsyms_expand_symbol(ctx, off, namebuf);

		if (strcmp(namebuf, name) == 0)
			return ctx->kallsyms_addresses[i];
	}
    return 0;
}

void kallsyms_free(kallsyms_t *ctx) {
    // stub
}

