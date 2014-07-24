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


#include <jni.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>

#include "log.h"
#include "root.h"

static int write_l(int fd, const void *data, size_t size) {
    size_t n, t;

    n = 0;
    while (n < size) {
        t = write(fd, (const char *) data + n, size - n);
        if (t < 0) {
            if (errno == -EINTR)
                continue;
            break;
        }
        n += t;
    }

    return n == size ? 0 : -1;
}

static int read_l(int fd, void *data, size_t size) {
    size_t n, t;

    n = 0;
    while (n < size) {
        t = read(fd, (char *) data + n, size - n);
        if (t < 0) {
            if (errno == -EINTR)
                continue;
            break;
        }
        n += t;
    }

    return n == size ? 0 : -1;
}

jint Java_org_stagex_root_RootSDK_root(JNIEnv *env, jclass clz, jstring cp) {
    int rc, msg;
    int p[2];
    root_ctx ctx;
    pid_t pid;

    rc = pipe(p);
    if (rc < 0) {
        LOGD("pipe() failed");
        return -1;
    }
    pid = fork();
    if (pid < 0) {
        LOGD("fork() failed");
        return -1;
    }
    if (pid) {
        sig_t olds;

        olds = signal(SIGPIPE, SIG_IGN);
        close(p[1]);
        msg = -1;
        rc = read_l(p[0], &msg, sizeof(msg));
        close(p[0]);
        signal(SIGPIPE, olds);
        return msg;
    } else {
        const char *ldlp;
        const char *cpcp;
        char *args[] = {
            "app_process",
            "/system/bin",
            "org.stagex.root.RootService",
            "--nice-name=tewilovesyouyet!",
            0
        };

        close(p[0]);
        LOGD("c: prepare");
        ldlp = getenv("LD_LIBRARY_PATH");
        if (cp) {
            const char *tmp;

            tmp = (*env)->GetStringUTFChars(env, cp, 0);
            if (tmp) {
                cpcp = strdup(tmp); // leak, but not to care
                (*env)->ReleaseStringUTFChars(env, cp, tmp);
            }
        }
        LOGD("c: root bgn");
        rc = root_init(&ctx);
        if (rc) {
            msg = rc;
            write_l(p[1], &msg, sizeof(msg));
            close(p[1]);
            exit(1);
        }
        rc = root_321(&ctx);
        root_free(&ctx);
        LOGV("c: root end, rc = %d, uid = %d", rc, getuid());
        msg = rc;
        write_l(p[1], &msg, sizeof(msg));
        close(p[1]);
        if (msg != 0) {
            LOGD("c: root_321() failed");
            exit(1);
        }
        LOGD("c: bring up service");
        LOGV("c: LD_LIBRARY_PATH=%s", ldlp);
        setenv("LD_LIBRARY_PATH", ldlp, 1);
        if (cpcp) {
            LOGV("c: CLASSPATH=%s", cpcp);
            setenv("CLASSPATH", cpcp, 1);
        }
        execvp(args[0], args);
        // should not be here
        exit(1);
    }
    return -1;
}

