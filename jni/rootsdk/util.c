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

#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

int dump(const char *fn, const void *addr, size_t size) {
    int fd;
    size_t off, tmp;

    fd = open(fn, O_CREAT | O_WRONLY, 0644);
    if (fd < 0) {
        LOGE("open()");
        return -1;
    }
    off = 0;
    for (;;) {
        tmp = write(fd, (char *) addr + off, size - off);
        if (tmp < 0) {
            if (errno == -EINTR)
                continue;
            LOGE("write()");
            break;
        }
        off += tmp;
        if (off == size)
            break;
    }
    close(fd);
    return off == size ? 0 : -1;
}

void trim(char *str) {
    char c;
    int i, l = -1, r = -1;

    for (i = 0; str[i]; i++) {
        c = str[i];
        if (l < 0) {
            if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
                continue;
            }
            else {
                l = i;
                continue;
            }
        }
        if (r < 0) {
            if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
                r = i;
                break;
            } else {
                continue;
            }
        }
    }
    if (l < 0)
        l = i;
    if (r < 0)
        r = i;
    if (r > l) {
        if (l > 0) {
            memmove(str, str + l, r - l);
        }
        if (str[i]) {
            str[r] = 0;
        }
    }
}

