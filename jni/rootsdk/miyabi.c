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


#include "miyabi.h"
#include "kconfig.h"
#include <string.h>

bool miyabi_exists() {
    int rc;
    char config_data[12];
    int config_size;

    memset(config_data, 0, sizeof(config_data));
    config_size = sizeof(config_data);
    rc = kconfig_get("CONFIG_SECURITY_MIYABI", config_data, &config_size);
    if (!rc && !strcmp(config_data, "y"))
        return true;

    return false;
}

