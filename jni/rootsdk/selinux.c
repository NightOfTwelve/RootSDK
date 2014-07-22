
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

