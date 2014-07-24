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


#ifndef _ROOT_H_
#define _ROOT_H_

#include "exploit.h"

#ifdef __cplusplus
extern "C" {
#endif

struct st_root_ctx {
    char my_name_old[16];
    char my_name_new[16];
    int lsm;
    int kconfig;
    exploit_t *exploits;
};

typedef struct st_root_ctx root_ctx;

int root_init(root_ctx *);
void root_free(root_ctx *);
/* TODO:
 quirks, e.g., currently kernel stack overflow will produce a zombie kernel thread
         and the user process will hang on (D) state at exit.
 */
int root_321(root_ctx *);

#ifdef __cplusplus
}
#endif

#endif

