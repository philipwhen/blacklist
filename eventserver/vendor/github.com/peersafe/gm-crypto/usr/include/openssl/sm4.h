#pragma once

#include <stdint.h>
#include <string.h>
#include "emmintrin.h"
#include "immintrin.h"
#include "tmmintrin.h"
#include "wmmintrin.h"
#include "pmmintrin.h"

#include <limits.h>
#define bitsof(x) (CHAR_BIT * sizeof(x))

#define rol(x, n) (((x) << (n)) | ((x) >> ((bitsof(x) - (n)))))
#define ror(x, n) (((x) >> (n)) | ((x) << ((bitsof(x) - (n)))))

#define sm4_round_NUM 32
#define sm4_block_BYTES 16
#define sm4_key_BYTES 16
#define sm4_iv_BYTES 16

#define byte_swap32 __builtin_bswap32
#define to_bigendian32 byte_swap32

#define RK(rk, n) (rk->val[n])
typedef struct { uint32_t val[sm4_round_NUM]; } sm4_key_t;
typedef struct { sm4_key_t ks; } EVP_SM4_KEY;

typedef struct { __m128i rk[sm4_round_NUM]; } sm4_key_p4_t;
typedef struct {
    sm4_key_p4_t ks;
    int buf_len;
    unsigned char buf[sm4_block_BYTES * 4];
    int num;

} EVP_SM4_P4_KEY;

extern const uint8_t sm4_sbox[256];
extern const uint32_t sm4_ck[32];
extern const uint32_t sbox0[256];
extern const uint32_t sbox1[256];
extern const uint32_t sbox2[256];
extern const uint32_t sbox3[256];
extern const uint32_t ks_sbox0[256];
extern const uint32_t ks_sbox1[256];
extern const uint32_t ks_sbox2[256];
extern const uint32_t ks_sbox3[256];
extern const uint32_t sm4_ck_p1[sm4_round_NUM];

void sm4_key_schedule_p1(const unsigned char *key, sm4_key_t *rk);
void sm4_enc_table_p1(unsigned char *m, const sm4_key_t *rk);
void sm4_dec_table_p1(unsigned char *m, const sm4_key_t *rk);

void sm4_encrypt_block(const unsigned char in[sm4_block_BYTES], unsigned char out[sm4_block_BYTES], const void *key);

void sm4_decrypt_block(const unsigned char in[sm4_block_BYTES], unsigned char out[sm4_block_BYTES], const void *key);

void sm4_key_schedule_p4(uint32_t const key[sm4_key_BYTES / sizeof(uint32_t)],
                         __m128i rk[sm4_round_NUM]);

void sm4_enc_aesni_p4(const uint32_t in[4 * sm4_block_BYTES / sizeof(uint32_t)],
                      uint32_t out[4 * sm4_block_BYTES / sizeof(uint32_t)],
                      const __m128i rk[sm4_round_NUM]);

void sm4_dec_aesni_p4(const uint32_t in[4 * sm4_block_BYTES / sizeof(uint32_t)],
                      uint32_t out[4 * sm4_block_BYTES / sizeof(uint32_t)],
                      const __m128i rk[sm4_round_NUM]);

__m128i sm4_enc_p1(const __m128i p, const sm4_key_t *rk);
void sm4_enc_p4(__m128i *x0, __m128i *x1, __m128i *x2, __m128i *x3,
                   const __m128i rk[32]);
