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


#ifndef _KSYMBOL_H_
#define _KSYMBOL_H_

#include "exploit.h"
#include "kconfig.h"

#ifdef __cplusplus
extern "C" {
#endif

// internal error
#define KSYMBOL_LOOKUP_500  -1
// symbol not found
#define KSYMBOL_LOOKUP_404  -2
// symbol found, but value is unknown
#define KSYMBOL_LOOKUP_200  0

long ksymbol_kallsyms_lookup(const char *);
long ksymbol_vector_lookup(int, const char *);
long ksymbol_exploit_lookup(exploit_t *, const char *);

#define ksymbol_exists(rc) (rc != KSYMBOL_LOOKUP_500 && rc != KSYMBOL_LOOKUP_404)
#define ksymbol_valid(rc) (rc != KSYMBOL_LOOKUP_500 && rc != KSYMBOL_LOOKUP_404 && rc != KSYMBOL_LOOKUP_200)

struct st_ksymbol_static_data {
    const char *model;
    const char *displayid;
    // XXX:
    // base must be page aligned
    // pbase must be corresponding to vbase
    long kernel_pbase;
    long kernel_vbase;
    long kernel_size;
    const char *victim_device;
    long victim_fops;
    long victim_syscall;
};

typedef struct st_ksymbol_static_data ksymbol_static_data_t;

extern ksymbol_static_data_t ksymbol_static_data[];

ksymbol_static_data_t *ksymbol_static_lookup(void);

int kernel_paddr_get(long *, long *);
int kernel_vaddr_get(long *, long *);

#ifdef __cplusplus
}
#endif

#endif

