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


#ifndef _KCONFIG_H_
#define _KCONFIG_H_

#ifdef __cplusplus
extern "C" {
#endif

#define CONFIG_CPU_ENDIAN_BE8 0x00000001
#define CONFIG_AEABI          0x00000002
#define CONFIG_ARM_THUMB      0x00000004
#define CONFIG_ALIGNMENT_TRAP 0x00000008
#define CONFIG_FRAME_POINTER  0x00000010
#define CONFIG_OABI_COMPAT    0x00000020
#define CONFIG_SECCOMP        0x00000040
#define CONFIG_KEYS           0x00000080

int kconfig_get(const char *, char *, int *);

#ifdef __cplusplus
}
#endif

#endif

