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


#include "ksymbol.h"

ksymbol_static_data_t ksymbol_static_data[] = {
    {
        .model = "SH-06E",
        .displayid = "01.00.07",
        .kernel_pbase = 0,
        .kernel_vbase = 0,
        .kernel_size = 0,
        .victim_device = "/dev/ptmx",
        .victim_fops = 0xc1050090,
        .victim_syscall = 0,
    },
    {
        .model = "SBM203SH",
        .displayid = "S0012",
        .kernel_pbase = 0,
        .kernel_vbase = 0,
        .kernel_size = 0,
        .victim_device = "/dev/ptmx",
        .victim_fops = 0xc0ef6580,
        .victim_syscall = 0,
    },
    { .model = 0 }
};

