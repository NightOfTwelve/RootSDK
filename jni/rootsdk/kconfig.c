
#include "log.h"
#include "kconfig.h"
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <malloc.h>
#include <zlib.h>

int kconfig_get(const char *name, char *val_data, int *val_size) {
    gzFile fd = 0;
    char *name_data = 0;
    char *config_data = 0, *tmp;
    int name_size, config_size = 0, off = 0;
    int ret = -1, rc, chunk = 4096, len;
    char *ps, *pe;

   fd = gzopen("/proc/config.gz", "r");
    if (!fd) {
        // LOGD("gzopen() failed.");
        return -1;
    }
    // CONFIG_XXX /=
    name_size = strlen(name) + 1;
    name_data = (char *) malloc(name_size);
    if (!name_data) {
        LOGE("malloc()");
        goto bail;
    }
    // load whole /proc/config.gz
    for (;;) {
        if (config_size == off) {
            config_size = config_size ? config_size * 2 : 0x1000;
            tmp = realloc(config_data, config_size);
            if (!tmp) {
                LOGE("realloc()");
                goto bail;
            }
            config_data = tmp;
        }
        rc = gzread(fd, config_data + off, chunk);
        if (rc < 0) {
            LOGD("gzread() failed.");
            goto bail;
        }
        off += rc;
        if (rc < chunk)
            break;
    }
    // check for "CONFIG_XXX=xxx"
    memcpy(name_data, name, name_size - 1);
    name_data[name_size - 1] = '=';
    ps = (char *) memmem(config_data, off, name_data, name_size);
    if (ps) {
        pe = (char *) memmem(ps + name_size, off - (ps - config_data + name_size), "\n", 1);
        if (pe) {
            tmp = ps;
            while (tmp >= config_data && *tmp != '\n')
                tmp--;
            if (*tmp == '\n')
                tmp++;
            ps = tmp;
            ps = (char *) memmem(ps, pe - ps, "=", 1);
            ps = ps + 1;
            len = pe - ps;
            if (val_data)
                memcpy(val_data, ps, len > *val_size ? *val_size : len);
            *val_size = len;
            ret = 0;
        } else {
            *val_size = -1;
            ret = 1;
            LOGD("malformed config.gz.");
        }
    } else {
        // check for "CONFIG_XXX is not set"
        memcpy(name_data, name, name_size - 1);
        name_data[name_size - 1] = ' ';
        ps = (char *) memmem(config_data, off, name_data, name_size);
        if (ps) {
            *val_size = 0;
            ret = 0;
        } else {
            *val_size = 0x80000000;
            ret = 0;
        }
   }
bail:
    if (name_data)
        free(name_data);
    if (config_data)
        free(config_data);
    if (fd) {
        rc = gzclose(fd);
        if (rc != Z_OK)
            LOGD("gzclose() failed.");
    }
    return ret;
}

