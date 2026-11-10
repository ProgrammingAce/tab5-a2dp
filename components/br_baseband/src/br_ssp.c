#include "br/br_ssp.h"

#include <string.h>

/* ---- SHA-256 (FIPS 180-4) ---- */
typedef struct {
    uint32_t h[8];
    uint8_t buf[64];
    size_t fill;
    uint64_t total;
} sha_t;

static const uint32_t kK[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

static uint32_t ror(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

static void sha_block(sha_t* s, const uint8_t* p)
{
    uint32_t w[64];
    for (int i = 0; i < 16; ++i) w[i] = (uint32_t)p[4 * i] << 24 | (uint32_t)p[4 * i + 1] << 16 | (uint32_t)p[4 * i + 2] << 8 | p[4 * i + 3];
    for (int i = 16; i < 64; ++i) {
        const uint32_t s0 = ror(w[i - 15], 7) ^ ror(w[i - 15], 18) ^ (w[i - 15] >> 3);
        const uint32_t s1 = ror(w[i - 2], 17) ^ ror(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = s->h[0], b = s->h[1], c = s->h[2], d = s->h[3], e = s->h[4], f = s->h[5], g = s->h[6], h = s->h[7];
    for (int i = 0; i < 64; ++i) {
        const uint32_t t1 = h + (ror(e, 6) ^ ror(e, 11) ^ ror(e, 25)) + ((e & f) ^ (~e & g)) + kK[i] + w[i];
        const uint32_t t2 = (ror(a, 2) ^ ror(a, 13) ^ ror(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    s->h[0] += a; s->h[1] += b; s->h[2] += c; s->h[3] += d;
    s->h[4] += e; s->h[5] += f; s->h[6] += g; s->h[7] += h;
}

static void sha_init(sha_t* s)
{
    static const uint32_t iv[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                   0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    memcpy(s->h, iv, sizeof iv);
    s->fill = 0;
    s->total = 0;
}

static void sha_update(sha_t* s, const uint8_t* p, size_t n)
{
    s->total += n;
    while (n) {
        const size_t take = 64 - s->fill < n ? 64 - s->fill : n;
        memcpy(s->buf + s->fill, p, take);
        s->fill += take;
        p += take;
        n -= take;
        if (s->fill == 64) {
            sha_block(s, s->buf);
            s->fill = 0;
        }
    }
}

static void sha_final(sha_t* s, uint8_t out[32])
{
    const uint64_t bits = s->total * 8;
    const uint8_t one = 0x80, zero = 0;
    sha_update(s, &one, 1);
    while (s->fill != 56) sha_update(s, &zero, 1);
    uint8_t len[8];
    for (int i = 0; i < 8; ++i) len[i] = (uint8_t)(bits >> (56 - 8 * i));
    sha_update(s, len, 8);
    for (int i = 0; i < 8; ++i) {
        out[4 * i] = (uint8_t)(s->h[i] >> 24);
        out[4 * i + 1] = (uint8_t)(s->h[i] >> 16);
        out[4 * i + 2] = (uint8_t)(s->h[i] >> 8);
        out[4 * i + 3] = (uint8_t)s->h[i];
    }
}

void br_sha256(const uint8_t* msg, size_t len, uint8_t out[32])
{
    sha_t s;
    sha_init(&s);
    sha_update(&s, msg, len);
    sha_final(&s, out);
}

void br_hmac_sha256(const uint8_t* key, size_t key_len, const uint8_t* msg, size_t len, uint8_t out[32])
{
    uint8_t k[64], pad[64], inner[32];
    memset(k, 0, sizeof k);
    if (key_len > 64) br_sha256(key, key_len, k);
    else memcpy(k, key, key_len);
    sha_t s;
    for (int i = 0; i < 64; ++i) pad[i] = k[i] ^ 0x36;
    sha_init(&s);
    sha_update(&s, pad, 64);
    sha_update(&s, msg, len);
    sha_final(&s, inner);
    for (int i = 0; i < 64; ++i) pad[i] = k[i] ^ 0x5c;
    sha_init(&s);
    sha_update(&s, pad, 64);
    sha_update(&s, inner, 32);
    sha_final(&s, out);
}

/* ---- SSP functions: little-endian arrays in, MSB-first streams to SHA-256 ---- */
static size_t put_be(uint8_t* dst, const uint8_t* le, size_t n)
{
    for (size_t i = 0; i < n; ++i) dst[i] = le[n - 1 - i];
    return n;
}

/* The 128 most significant bits of the HMAC output: its first 16 octets, MSB first. */
static void top128(const uint8_t mac[32], uint8_t out[16])
{
    for (int i = 0; i < 16; ++i) out[i] = mac[15 - i];
}

void br_ssp_f1(const uint8_t* u, const uint8_t* v, size_t key_len, const uint8_t x[16], uint8_t z, uint8_t out[16])
{
    uint8_t msg[32 + 32 + 1], key[16], mac[32];
    size_t n = put_be(msg, u, key_len);
    n += put_be(msg + n, v, key_len);
    msg[n++] = z;
    put_be(key, x, 16);
    br_hmac_sha256(key, 16, msg, n, mac);
    top128(mac, out);
}

uint32_t br_ssp_g(const uint8_t* u, const uint8_t* v, size_t key_len, const uint8_t x[16], const uint8_t y[16])
{
    uint8_t msg[32 + 32 + 16 + 16], dig[32];
    size_t n = put_be(msg, u, key_len);
    n += put_be(msg + n, v, key_len);
    n += put_be(msg + n, x, 16);
    n += put_be(msg + n, y, 16);
    br_sha256(msg, n, dig);
    return (uint32_t)dig[28] << 24 | (uint32_t)dig[29] << 16 | (uint32_t)dig[30] << 8 | dig[31];
}

void br_ssp_f2(const uint8_t* w, size_t key_len, const uint8_t n1[16], const uint8_t n2[16], uint32_t key_id,
               const uint8_t a1[6], const uint8_t a2[6], uint8_t out[16])
{
    uint8_t msg[16 + 16 + 4 + 6 + 6], key[32], mac[32];
    size_t n = put_be(msg, n1, 16);
    n += put_be(msg + n, n2, 16);
    msg[n++] = (uint8_t)(key_id >> 24);
    msg[n++] = (uint8_t)(key_id >> 16);
    msg[n++] = (uint8_t)(key_id >> 8);
    msg[n++] = (uint8_t)key_id;
    n += put_be(msg + n, a1, 6);
    n += put_be(msg + n, a2, 6);
    put_be(key, w, key_len);
    br_hmac_sha256(key, key_len, msg, n, mac);
    top128(mac, out);
}

void br_ssp_f3(const uint8_t* w, size_t key_len, const uint8_t n1[16], const uint8_t n2[16], const uint8_t r[16],
               const uint8_t iocap[3], const uint8_t a1[6], const uint8_t a2[6], uint8_t out[16])
{
    uint8_t msg[16 + 16 + 16 + 3 + 6 + 6], key[32], mac[32];
    size_t n = put_be(msg, n1, 16);
    n += put_be(msg + n, n2, 16);
    n += put_be(msg + n, r, 16);
    n += put_be(msg + n, iocap, 3);
    n += put_be(msg + n, a1, 6);
    n += put_be(msg + n, a2, 6);
    put_be(key, w, key_len);
    br_hmac_sha256(key, key_len, msg, n, mac);
    top128(mac, out);
}
