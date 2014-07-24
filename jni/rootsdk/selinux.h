
#ifndef _SE_LINUX_H_
#define _SE_LINUX_H_

#ifdef __cplusplus
extern "C" {
#endif

int selinux_enforce_get();
int selinux_attr_set_priv();

#ifdef __cplusplus
}
#endif

#endif

