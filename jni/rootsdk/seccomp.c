
#include "seccomp.h"
#include <unistd.h>
#include <sys/prctl.h>

#ifndef PR_GET_SECCOMP
#define PR_GET_SECCOMP 21
#endif

// XXX: when kernel introduced this?
int seccomp_get(int *seccomp) {
    return prctl(PR_GET_SECCOMP, 0, 0, 0);
}



