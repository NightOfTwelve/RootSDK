
#ifndef _UTIL_H_
#define _UTIL_H_

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

int dump(const char *, const void *, size_t);
void trim(char *);

#ifdef __cplusplus
}
#endif

#endif

