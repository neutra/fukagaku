
#include <stdint.h>
#include <memory.h>
#include <stdio.h>

#include <openssl/sha.h>

static uint8_t salt0[20] = {
0x40, 0x94, 0x48, 0x85, 0x3e, 0x47, 0x2c, 0x52, 0xd8, 0x53, 0x16, 0xb0, 0xa2, 0x66, 0x43, 0xac, 0xe0, 0x77, 0x89, 0xde
};

static uint8_t salt1[20] = {
0x63, 0x03, 0x2e, 0x10, 0xfe, 0xc6, 0x80, 0xff, 0x18, 0x15, 0xc6, 0xae, 0x6f, 0x4a, 0xf2, 0x5e, 0xd1, 0x72, 0x04, 0x05
};

// STEP:
//  t = NCK + SALT
//  h = sha256(t)
//  9.times { h = sha256(h) }
//  assert(h == HASH)
// IMEI: 353588050129797
// NCK : 6477654217628843
// HASH:
// 3d 3c 67 e3 35 a1 7a 6c df 02 e2 fe d0 4c 1c ae
// 9b a0 4d 2c 85 27 25 59 16 55 79 03 11 9b 38 45
// SALT:
static uint8_t salt2[20] = {
0x12, 0x8a, 0xf4, 0xa1, 0xcb, 0x62, 0xcb, 0x1d, 0x9b, 0x18, 0x0b, 0x74, 0x17, 0x12, 0xab, 0xb3, 0x3c, 0x74, 0x49, 0xe2
};

static uint8_t salt3[20] = {
0xaa, 0xe8, 0x7c, 0x7c, 0x1e, 0xb5, 0xbc, 0x9a, 0x9e, 0x5b, 0x68, 0x14, 0x27, 0xfc, 0xbf, 0x01, 0xbc, 0x58, 0x24, 0xf2
};

static uint8_t salt4[20] = {
0x0f, 0x8b, 0xa3, 0x61, 0x9b, 0x06, 0x2f, 0xc8, 0x83, 0xb2, 0x8f, 0x34, 0x1d, 0x6b, 0x04, 0xc1, 0xe1, 0x12, 0x38, 0x47
};

char *code = "6477654217628843";

static void memdump(const void *data, size_t size) {
        size_t i;
        unsigned char *p;

        for (i = 0; i < size; i++) {
                p = (unsigned char *) data + i;
                printf("%02x ", *p);
                if (((i + 1) % 16 == 0)) printf("\n");
        }
        if (i % 16) printf("\n");
}


int main() {
	int n, i;
	char *salt[] = {salt0, salt1, salt2, salt3, salt4};
	char buffer[36];
	SHA256_CTX ctx;
	uint8_t hash[32];

	for (n = 0; n < sizeof(salt) / sizeof(salt[0]); n++) {
		memcpy(buffer, code, 16);
		memcpy(buffer + 16, salt[n], 20);
		// round 0
		SHA256_Init(&ctx);
		SHA256_Update(&ctx, buffer, sizeof(buffer));
		SHA256_Final(hash, &ctx);
		// round 1 - 9
		for (i = 0; i < 9; i++) {
			SHA256_Init(&ctx);
			SHA256_Update(&ctx, hash, 32);
			SHA256_Final(hash, &ctx);
		}
		memdump(hash, 32);
		printf("\n");
	}
	
	return 0;
}
