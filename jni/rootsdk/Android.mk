LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := root
LOCAL_ARM_MODE := arm
LOCAL_SRC_FILES := \
    kallsyms.c \
    ksymbol.c \
    ksymbol_static_data.c \
    kconfig.c \
    exploit.c \
    seccomp.c \
    util.c \
    selinux.c \
    miyabi.c \
    root.c \
    bomb_cve_2014_3153.c \
    bomb_cve_2013_6282.c \
    bomb_mtk.c \
    bomb_vivante.c
LOCAL_CFLAGS += -Wall
LOCAL_STATIC_LIBRARIES += zlib
LOCAL_EXPORT_C_INCLUDES := $(LOCAL_PATH)
LOCAL_EXPORT_LDLIBS += -llog
include $(BUILD_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := rootsdk
LOCAL_ARM_MODE := arm
LOCAL_SRC_FILES := jni.c
LOCAL_STATIC_LIBRARIES += root
LOCAL_LDLIBS += -llog
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := rootsdk_test
LOCAL_ARM_MODE := arm
LOCAL_SRC_FILES := main.c
LOCAL_STATIC_LIBRARIES += root
LOCAL_LDLIBS += -llog
include $(BUILD_EXECUTABLE)

