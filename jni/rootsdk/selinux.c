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
#include "selinux.h"

#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdio.h>

int selinux_enforce_get() {
    int fd, n, ret;
    char text[4];

    fd = open("/sys/fs/selinux/enforce", O_RDONLY);
    if (fd < 0) {
        // LOGE("open");
        return -1;
    }
    n = read(fd, text, sizeof(text));
    if (n < 0)
        LOGE("read()");
    close(fd);
    if (n <= 0)
        return -1;
    if (sscanf("%d", text, &ret) == 1)
        return ret;
    return -1;
}

int selinux_attr_set_priv() {
    int fd, n;

    fd = open("/proc/self/attr/current", O_WRONLY);
    if (fd < 0) {
        // LOGE("open()");
        return -1;
    }
    n = write(fd, "u:r:init:s0\n", 12);
    if (n < 0)
        LOGE("write()");
    close(fd);
    return n == 12 ? 0 : -1;
}

