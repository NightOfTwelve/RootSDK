
#include "log.h"
#include "root.h"
#include <unistd.h>

#include "kconfig.h"

int main(int argc, char *argv[]) {
    int rc;
    root_ctx ctx;

    rc = root_init(&ctx);
    if (rc < 0)
        return 1;
    rc = root_321(&ctx);
    root_free(&ctx);

    if (!rc) {
        LOGV("GOT ROOT!");
        rc = execl("/system/bin/sh", "/system/bin/sh", NULL);
    }

    return rc ? 1 : 0;
}

