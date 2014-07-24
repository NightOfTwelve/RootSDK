
#include "miyabi.h"
#include "kconfig.h"
#include <string.h>

bool miyabi_exists() {
    int rc;
    char config_data[12];
    int config_size;

    memset(config_data, 0, sizeof(config_data));
    config_size = sizeof(config_data);
    rc = kconfig_get("CONFIG_SECURITY_MIYABI", config_data, &config_size);
    if (!rc && !strcmp(config_data, "y"))
        return true;

    return false;
}

