
#ifndef _ROOT_H_
#define _ROOT_H_

#include "exploit.h"

#ifdef __cplusplus
extern "C" {
#endif

struct st_root_ctx {
    char my_name_old[16];
    char my_name_new[16];
    int lsm;
    int kconfig;
    exploit_t *exploits;
};

typedef struct st_root_ctx root_ctx;

int root_init(root_ctx *);
void root_free(root_ctx *);
/* TODO:
 quirks, e.g., currently kernel stack overflow will produce a zombie kernel thread
         and the user process will hang on (D) state at exit.
 */
int root_321(root_ctx *);

#ifdef __cplusplus
}
#endif

#endif

