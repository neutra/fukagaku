/*****************************************************************************
 * sharp_qxdm_enable.c : Program to enable DIAG mode on SHARP devices.
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

#include <sys/types.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <string.h>

#define SHDIAG_IOC_MAGIC 's'
#define SHDIAG_IOCTL_SET_QXDMFLG          _IOW  (SHDIAG_IOC_MAGIC,  1, unsigned char)

int main(int argc, char *argv[]) {
	int fd, rc;
	char enabled = 1;

	fd = open("/dev/smd_read", O_RDWR);
	if (fd < 0) {
		perror("open");
		return 1;
	}
	rc = ioctl(fd, SHDIAG_IOCTL_SET_QXDMFLG, &enabled);
	close(fd);
	return rc;
}

