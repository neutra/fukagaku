/*****************************************************************************
 * hrodat.c : SHARP SD loader encrypt and decrypt.
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

#include <errno.h>
#include <malloc.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/aes.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#pragma pack(push)
#pragma pack(1)
struct st_hrodat_hdr {
	uint8_t magic[12];	// SDUPDATERSEC
	uint8_t version[4];	// D001
	uint8_t brand[6];	// DOCOMO
	uint8_t model[6];	// DL32_a
	uint32_t unknown1;
	uint32_t sum;
	uint32_t unknown2;
	uint32_t unknown3;
	uint32_t size;		// = size - sizeof(st_hrodat_hdr)
};
#pragma pack(pop)

static uint8_t s_aes_key_dcm[] = {
	0x36, 0x7E, 0xA4, 0xAB, 0xDA, 0x4E, 0x35, 0xC6, 0xCF, 0x6F, 0x8E, 0xED, 0x15, 0xE1, 0x7D, 0x65, 
	0x68, 0x60, 0x78, 0x2E, 0x50, 0x73, 0xC5, 0x49, 0x45, 0x94, 0x62, 0x70, 0x47, 0xC2, 0x51, 0xE8, 
	0x61, 0x51, 0x44, 0xD2, 0xC5, 0xA1, 0xF3, 0xC8, 0xCE, 0x41, 0x5E, 0x11, 0x00, 0x33, 0x2B, 0xAD, 
	0xEB, 0x7C, 0x6B, 0x57, 0x4F, 0x4C, 0xA7, 0x4D, 0x70, 0x6F, 0x05, 0xDA, 0x8A, 0xDE, 0xDF, 0x51
};

static uint8_t s_aes_key_sb[] = {
	0xEF, 0x38, 0xA1, 0x64, 0x93, 0x07, 0xEE, 0x7F, 0x88, 0x28, 0x8B, 0xA6, 0xCE, 0x9A, 0x36, 0x62, 
	0x65, 0x5D, 0x75, 0xE8, 0x09, 0x2D, 0xC2, 0x02, 0xFE, 0x4D, 0x60, 0x6D, 0x44, 0xBF, 0x0A, 0xE6, 
	0x25, 0x73, 0xC7, 0xF0, 0x99, 0x43, 0x73, 0xEE, 0x82, 0x62, 0xD1, 0x7B, 0xC4, 0xDC, 0xEF, 0xF2, 
	0x68, 0x1E, 0xEB, 0xB9, 0xCC, 0x6E, 0x26, 0x93, 0xF1, 0x09, 0x85, 0xFF, 0x0B, 0xFB, 0x92, 0x77
};

static uint32_t s_aes_key_mask = 0x13b9c52a;

struct hrodat_supported_device {
	uint8_t *name;
	uint8_t *version;
	uint8_t *brand;
	uint8_t *model;
	uint8_t *key;
	uint32_t *mask;
};

static struct hrodat_supported_device devices[] = {
	{"SH12C", "D001", "DOCOMO", "DC40_a", s_aes_key_dcm, 0},				// not sure
	{"SH06E", "D001", "DOCOMO", "DL32_a", s_aes_key_dcm, &s_aes_key_mask},				// not sure
	{"007SH", "S001", "SBMSBM", "PA04_a", s_aes_key_sb, &s_aes_key_mask},	// confirmed
	{"101SH", "S001", "SBMSBM", "PA06_a", s_aes_key_sb, 0},					// confirmed
	{"203SH", "S001", "SBMSBM", "PA16_a", s_aes_key_sb, &s_aes_key_mask},	// not sure
	{0, 0, 0, 0, 0}
};

static uint32_t hrodat_hdr_calc_sum(const uint8_t *data, uint32_t size) {
	uint32_t i, sum = 0;

	for (i = 0; i < size; i++)
		sum += data[i];
	return sum;
}

static int hrodat_hdr_comp_ver(const uint8_t *user, const uint8_t *expected) {
	return 0;
}

static int hrodat_verify(const void *data, uint32_t size) {
	const struct st_hrodat_hdr *h = (const struct st_hrodat_hdr *) data;
	const struct hrodat_supported_device *d;

	if (memcmp(h->magic, "SDUPDATERSEC", 12))
		return -1;
	for (d = devices; d->name; d++) {
		if (!memcmp(h->brand, d->brand, 6) &&
			!memcmp(h->model, d->model, 6) &&
			!hrodat_hdr_comp_ver(h->version, d->version))
			break;
	}
	if (!d->name)
		return -2;
	if (h->size != size - sizeof(struct st_hrodat_hdr))
		return -3;
	return h->sum == hrodat_hdr_calc_sum((const uint8_t *) data + sizeof(*h), h->size) ? 0 : -4;
}

#define MODE_DECRYPT 0
#define MODE_ENCRYPT 1

static int hrodat_transform(const struct hrodat_supported_device *d, int mode, const uint8_t *id, uint8_t *od, uint32_t size) {
	int i;
	uint8_t key[32];
	uint32_t p = 1;
	uint8_t state[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
	uint8_t tmp8;
	uint32_t tmp32;
	struct aes_key_st ctx;

	if (d->mask) {
		memcpy(key, d->key + 32, 32);
		for (i = 0; i < 8; i++)
			*((uint32_t *)(key + i * 4)) ^= *(d->mask);
	} else {
		memcpy(key, d->key, 32);
	}
	AES_set_encrypt_key(key, 128, &ctx);
	if (mode) {
		while (p && size) {
			tmp8 = *id++ ^ state[p];
			*od++ = tmp8;
			state[p] = tmp8;
			size--;
			p = (p + 1) & 0x0f;
		}
		if (((intptr_t) id | (intptr_t) od | (intptr_t) state) & 3) {
			if (size) {
				i = 0;
				do {
					if (!p)
						AES_encrypt(state, state, &ctx);
					tmp8 = id[i] ^ state[p];
					od[i] = tmp8;
					state[p] = tmp8;
					p = (p + 1) & 0x0f;
				} while (i++ < size);
			}
			return 0;
		}
		while (size >= 0x10) {
			AES_encrypt(state, state, &ctx);
			for (p = 0; p < 0x10; p += 4) {
				tmp32 = *((uint32_t *)(id + p)) ^ *((uint32_t *)(state + p));
				*((uint32_t *)(od + p)) = tmp32;
				*((uint32_t *)(state + p)) = tmp32;
			}
			id += 16;
			od += 16;
			size -= 16;
		}
		if (size) {
			AES_encrypt(state, state, &ctx);
			p = 0;
			do {
				tmp8 = id[p] ^ state[p];
				od[p] = tmp8;
				state[p++] = tmp8;
			} while (size--);
		}
		return 0;
	}
	while (p && size) {
		tmp8 = *id++;
		*od++ = tmp8 ^ state[p];
		state[p] = tmp8;
		size--;
		p = (p + 1) & 0x0f;
	}
	if (((intptr_t) id | (intptr_t) od | (intptr_t) state) & 3) {
		if (size) {
			i = 0;
			do {
				if (!p)
					AES_encrypt(state, state, &ctx);
				tmp8 = id[i];
				od[i] = state[p] ^ tmp8;
				state[p] = tmp8;
				p = (p + 1) & 0x0f;
			} while (i++ < size);
		}
		return 0;
	}
	while (size >= 0x10) {
		AES_encrypt(state, state, &ctx);
		for (p = 0; p < 0x10; p += 4) {
			tmp32 = *((uint32_t *)(id + p));
			*((uint32_t *)(od + p)) = *((uint32_t *)(state + p)) ^ tmp32;
			*((uint32_t *)(state + p)) = tmp32;
		}
		id += 16;
		od += 16;
		size -= 16;
	}
	if (size) {
		AES_encrypt(state, state, &ctx);
		p = 0;
		do {
			tmp8 = id[p];
			od[p] = state[p] ^ tmp8;
			state[p++] = tmp8;
		} while (size--);
	}
	return 0;
}

static void usage(int argc, char *argv[]) {
	fprintf(stderr, "Usage:\n%s <e|d> <device> <ifile> <ofile>\n", argv[0]);
	exit(1);
}

int main(int argc, char *argv[]) {
	char *m, *dev, *fi, *fo;
	int mode, fdi, fdo, size, n, t, chunk, rc;
	struct stat fs;
	char *bi, *bo;
	struct hrodat_supported_device *d;
	struct st_hrodat_hdr *hdr;

	rc = 1;
	if (argc != 5)
		usage(argc, argv);
	m = argv[1];
	dev = argv[2];
	fi = argv[3];
	fo = argv[4];
	if (!strcmp(m, "d"))
		mode = 0;
	else if (!strcmp(m, "e"))
		mode = 1;
	else
		usage(argc, argv);
	for (d = devices; d->name; d++) {
		if (!strcmp(d->name, dev))
			break;
	}
	if (!d->name)
		return rc;
	fdi = open(fi, O_RDONLY);
	if (fdi < 0) {
		perror("open");
		goto fail_open_i;
	}
	size = lseek(fdi, 0, SEEK_END);
	if (size == (off_t) -1) {
		perror("lseek");
		goto fail_lseek_i;
	}
	bi = mmap(0, size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fdi, 0);
	if (bi == MAP_FAILED) {
		perror("mmap");
		goto fail_mmap_i;
	}
	bo = (char *) malloc(size);
	if (!bo) {
		perror("malloc");
		goto fail_malloc;
	}
	if (mode == MODE_ENCRYPT) {
		rc = hrodat_verify(bi, size);
		if (rc < 0)
			fprintf(stderr, "verify failed with %d.\n", rc);
			// we may not know brand and device, but we can fix sum and size
			if (rc < -2) {
				hdr = (struct st_hrodat_hdr *) bi;
				hdr->size = size - sizeof(*hdr);
				hdr->sum = hrodat_hdr_calc_sum(bi + sizeof(*hdr), hdr->size);
			}

	}
	rc = hrodat_transform(d, mode, bi, bo, size);
	if (rc < 0) {
		fprintf(stderr, "transform failed.\n");
		goto fail_hrodat_transform;
	}
	if (mode == MODE_DECRYPT) {
		rc = hrodat_verify(bo, size);
		if (rc < 0)
			fprintf(stderr, "verify failed with %d.\n", rc);
	}
	// write
	fdo = open(fo, O_CREAT | O_WRONLY, 0644);
	if (fdo < 0) {
		perror("open");
		goto fail_open_o;
	}
	n = 0;
	while (n < size) {
		chunk = size - n;
		if (chunk > 0x8000)
			chunk = 0x8000;
		t = write(fdo, bo + n, chunk);
		if (t < 0) {
			if (errno == -EINTR)
				continue;
			break;
		}
		if (t == 0)
			break;
		n += t;
	}
	if (n == size)
		rc = 0;
fail_write_o:
	close(fdo);
fail_open_o:
fail_hrodat_verify:
fail_hrodat_transform:
	free(bo);
fail_malloc:
fail_mmap_i:
fail_lseek_i:
	close(fdi);
fail_open_i:
	return rc;
}

