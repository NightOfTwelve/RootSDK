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
#include "root.h"
#include <unistd.h>

#include "kconfig.h"

int main(int argc, char *argv[]) {
    int rc;
    root_ctx ctx;

    rc = root_init(&ctx);
    if (rc < 0)
        return 1;
    rc = root_321(&ctx);
    root_free(&ctx);

    if (!rc) {
        LOGV("GOT ROOT!");
        rc = execl("/system/bin/sh", "/system/bin/sh", NULL);
    }

    return rc ? 1 : 0;
}

