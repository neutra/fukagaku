/*****************************************************************************
 * roprop.c : Program to let you edit Android ro property.
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

#include <stdio.h>
#include <sys/ptrace.h>
#include <errno.h>
#include <memory.h>
#include <string.h>

int main(int argc, char **argv) {
	int rc;
	unsigned long maps, mape, addr, test, fake;
	FILE *fp;
	char line[512];
	char *buffer, *ro;

	fp = fopen("/proc/1/maps", "r");
	if (!fp) {
		perror("fopen");
		return 1;
	}
	memset(line, 0, sizeof(line));
	fgets(line, sizeof(line), fp);
	fclose(fp);
	rc = sscanf(line, "%08x-%08x", &maps, &mape);
	if (rc < 2) {
		perror("sscanf");
		return 1;
	}
	buffer = (char *) malloc(mape - maps);
	if (!buffer) {
		perror("malloc");
		return 1;
	}
	rc = ptrace(PTRACE_ATTACH, 1, 0, 0);
	if (rc < 0) {
		perror("ptrace");
		return rc;
	}
	for (addr = maps; addr < mape; addr += 4) {
		test = ptrace(PTRACE_PEEKTEXT, 1, (void *) addr, 0);
		*((unsigned long *)(buffer + addr - maps)) = test;
	}
	// only appears once
	ro = memmem(buffer, mape - maps, "ro.", 4);
	if (ro) {
		printf("Patching init.\n");
		fake = 0;
		rc = ptrace(PTRACE_POKETEXT, 1, (void *)(maps + ro - buffer), &fake);
		if (rc < 0) {
			perror("ptrace");
		}
	}
	free(buffer);
	rc = ptrace(PTRACE_DETACH, 1, 0, 0);

	return rc;
}

