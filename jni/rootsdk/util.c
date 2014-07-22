
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

