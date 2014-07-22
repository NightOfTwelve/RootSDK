
#ifndef _KCONFIG_H_
#define _KCONFIG_H_

#define CONFIG_CPU_ENDIAN_BE8 0x00000001
#define CONFIG_AEABI          0x00000002
#define CONFIG_ARM_THUMB      0x00000004
#define CONFIG_ALIGNMENT_TRAP 0x00000008
#define CONFIG_FRAME_POINTER  0x00000010
#define CONFIG_OABI_COMPAT    0x00000020
#define CONFIG_SECCOMP        0x00000040
#define CONFIG_KEYS           0x00000080

int kconfig_get(const char *, char *, int *);

#endif

