#include "br/br_safer.h"

#include <string.h>

/* e(x) = 45^x mod 257 (with 256 represented as 0), l = its inverse. Core Vol 2 Part H §6.1. */
static uint8_t s_exp[256], s_log[256];
static int s_tables;

static void tables(void)
{
    unsigned v = 1;
    for (int i = 0; i < 256; ++i) {
        s_exp[i] = (uint8_t)(v & 0xFF); /* 45^128 mod 257 = 256 -> 0 */
        s_log[v & 0xFF] = (uint8_t)i;
        v = (v * 45u) % 257u;
    }
    s_tables = 1;
}

/* Byte positions that use XOR for the first key addition (and addition mod 256 for the second). */
static int xor_pos(int i)
{
    const int m = i & 3;
    return m == 0 || m == 3;
}

void br_safer_keys(const uint8_t key[16], uint8_t keys[17][16])
{
    if (!s_tables) tables();
    uint8_t k[17];
    memcpy(k, key, 16);
    k[16] = 0;
    for (int i = 0; i < 16; ++i) k[16] ^= key[i];
    memcpy(keys[0], key, 16);
    for (int p = 2; p <= 17; ++p) {
        for (int i = 0; i < 17; ++i) k[i] = (uint8_t)((k[i] << 3) | (k[i] >> 5));
        for (int j = 0; j < 16; ++j) {
            const uint8_t bias = s_exp[s_exp[(17 * p + j + 1) & 0xFF]];
            keys[p - 1][j] = (uint8_t)(k[(p - 1 + j) % 17] + bias);
        }
    }
}

/* Armenian shuffle. */
static const uint8_t kPerm[16] = {8, 11, 12, 15, 2, 1, 6, 5, 10, 9, 14, 13, 0, 7, 4, 3};

static void linear(uint8_t x[16])
{
    for (int level = 0; level < 4; ++level) {
        for (int i = 0; i < 16; i += 2) {
            const uint8_t a = x[i], b = x[i + 1];
            x[i] = (uint8_t)(2 * a + b);
            x[i + 1] = (uint8_t)(a + b);
        }
        if (level < 3) {
            uint8_t t[16];
            for (int i = 0; i < 16; ++i) t[i] = x[kPerm[i]];
            memcpy(x, t, 16);
        }
    }
}

void br_safer_encrypt(const uint8_t key[16], const uint8_t in[16], int prime, uint8_t out[16], uint8_t rounds[9][16])
{
    uint8_t keys[17][16];
    br_safer_keys(key, keys);
    uint8_t x[16];
    memcpy(x, in, 16);
    for (int r = 0; r < 8; ++r) {
        if (rounds) memcpy(rounds[r], x, 16);
        if (r == 2) {
            if (prime)
                for (int i = 0; i < 16; ++i) x[i] = xor_pos(i) ? (uint8_t)(x[i] ^ in[i]) : (uint8_t)(x[i] + in[i]);
            if (rounds) memcpy(rounds[8], x, 16);
        }
        const uint8_t* k1 = keys[2 * r];
        const uint8_t* k2 = keys[2 * r + 1];
        for (int i = 0; i < 16; ++i) {
            if (xor_pos(i)) x[i] = s_exp[(uint8_t)(x[i] ^ k1[i])];
            else x[i] = s_log[(uint8_t)(x[i] + k1[i])];
            x[i] = xor_pos(i) ? (uint8_t)(x[i] + k2[i]) : (uint8_t)(x[i] ^ k2[i]);
        }
        linear(x);
    }
    for (int i = 0; i < 16; ++i) out[i] = xor_pos(i) ? (uint8_t)(x[i] ^ keys[16][i]) : (uint8_t)(x[i] + keys[16][i]);
}

/* K~ offset for the second stage of E1/E3 (Core Vol 2 Part H §6.3). */
static void offset_key(const uint8_t k[16], uint8_t out[16])
{
    static const uint8_t c[8] = {233, 229, 223, 193, 179, 167, 149, 131};
    for (int i = 0; i < 16; ++i) {
        const uint8_t v = c[i & 7];
        /* bytes 0,2,4,6,11,13,15 and 9: add; the others XOR - pattern: add on even i < 8 and odd i >= 8 */
        const int add = (i < 8) ? !(i & 1) : (i & 1);
        out[i] = add ? (uint8_t)(k[i] + v) : (uint8_t)(k[i] ^ v);
    }
}

/* Hash(K, I1, I2, L) = A'r(K~, [Ar(K, I1) XOR I1] +16 E(I2, L)), E = cyclic expansion of I2 (L bytes) to 16. */
static void hash(const uint8_t k[16], const uint8_t i1[16], const uint8_t* i2, size_t l, uint8_t out[16])
{
    uint8_t t[16], kt[16];
    br_safer_encrypt(k, i1, 0, t, NULL);
    for (int i = 0; i < 16; ++i) t[i] = (uint8_t)((t[i] ^ i1[i]) + i2[i % l]);
    offset_key(k, kt);
    br_safer_encrypt(kt, t, 1, out, NULL);
}

void br_e1(const uint8_t key[16], const uint8_t rand[16], const uint8_t bd_addr[6], uint8_t sres[4], uint8_t aco[12])
{
    uint8_t out[16];
    hash(key, rand, bd_addr, 6, out);
    memcpy(sres, out, 4);
    memcpy(aco, out + 4, 12);
}

void br_e21(const uint8_t rand[16], const uint8_t bd_addr[6], uint8_t out[16])
{
    uint8_t x[16], y[16];
    memcpy(x, rand, 16);
    x[15] ^= 6;
    for (int i = 0; i < 16; ++i) y[i] = bd_addr[i % 6];
    br_safer_encrypt(x, y, 1, out, NULL);
}

void br_e22(const uint8_t rand[16], const uint8_t* pin, size_t pin_len, const uint8_t bd_addr[6], uint8_t out[16])
{
    uint8_t pinp[16], key[16], x[16];
    if (pin_len > 16) pin_len = 16;
    size_t l = pin_len;
    memcpy(pinp, pin, pin_len);
    for (size_t i = 0; l < 16 && i < 6; ++i) pinp[l++] = bd_addr[i];
    for (int i = 0; i < 16; ++i) key[i] = pinp[i % l];
    memcpy(x, rand, 16);
    x[15] ^= (uint8_t)l;
    br_safer_encrypt(key, x, 1, out, NULL);
}

void br_e3(const uint8_t key[16], const uint8_t rand[16], const uint8_t cof[12], uint8_t kc[16])
{
    hash(key, rand, cof, 12, kc);
}
