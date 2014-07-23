
#include "ksymbol.h"

ksymbol_static_data_t ksymbol_static_data[] = {
    {
        .model = "SH-06E",
        .displayid = "01.00.07",
        .kernel_pbase = 0,
        .kernel_vbase = 0,
        .kernel_size = 0,
        .victim_device = "/dev/ptmx",
        .victim_fops = 0xc1050090,
        .victim_syscall = 0,
    },
    {
        .model = "SBM203SH",
        .displayid = "S0012",
        .kernel_pbase = 0,
        .kernel_vbase = 0,
        .kernel_size = 0,
        .victim_device = "/dev/ptmx",
        .victim_fops = 0xc0ef6580,
        .victim_syscall = 0,
    },
    { .model = 0 }
};

