
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

