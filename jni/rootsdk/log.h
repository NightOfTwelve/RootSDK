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


#ifndef _LOG_H_
#define _LOG_H_

#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <android/log.h>

#define TAG "RootSDK"
#define LOG(...) do { \
    flockfile(stderr); \
    fprintf(stderr, __VA_ARGS__); \
    fprintf(stderr, "\n"); \
    fflush(stderr); \
    funlockfile(stderr); \
    __android_log_print(ANDROID_LOG_VERBOSE, TAG, __VA_ARGS__); \
    } while (0)

#define LOGV(...) LOG(__VA_ARGS__)

//#ifndef NDEBUG
#if 1
#define LOGD(what) LOG("%s:%s:%d: %s", __FILE__, __func__, __LINE__, what)
#define LOGE(what) LOG("%s:%s:%d: %s failed with %d, %s.", __FILE__, __func__, __LINE__, what, errno, strerror(errno))
#else
#define LOGD(what)
#define LOGE(what)
#endif

#endif

