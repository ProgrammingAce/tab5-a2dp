#include "br/br_e0.h"

#include <string.h>

#include "br/br_bits.h"

/* g1(L) without its leading x^(8L) term, and g2(L), as {low 64 bits, high 64 bits}. Core Vol 2 Part H Table 4.4 */
static const uint64_t kG1[15][2] = {
    {0x000000000000001Dull, 0x0000000000000000ull}, /* L=1 */
    {0x000000000000003Full, 0x0000000000000000ull}, /* L=2 */
    {0x00000000000000DBull, 0x0000000000000000ull}, /* L=3 */
    {0x00000000000000AFull, 0x0000000000000000ull}, /* L=4 */
    {0x0000000000000039ull, 0x0000000000000000ull}, /* L=5 */
    {0x0000000000000291ull, 0x0000000000000000ull}, /* L=6 */
    {0x0000000000000095ull, 0x0000000000000000ull}, /* L=7 */
    {0x000000000000001Bull, 0x0000000000000000ull}, /* L=8 */
    {0x0000000000000609ull, 0x0000000000000000ull}, /* L=9 */
    {0x0000000000000215ull, 0x0000000000000000ull}, /* L=10 */
    {0x000000000000013Bull, 0x0000000000000000ull}, /* L=11 */
    {0x00000000000000DDull, 0x0000000000000000ull}, /* L=12 */
    {0x000000000000049Dull, 0x0000000000000000ull}, /* L=13 */
    {0x000000000000014Full, 0x0000000000000000ull}, /* L=14 */
    {0x00000000000000E7ull, 0x0000000000000000ull}, /* L=15 */
};
static const uint64_t kG2[15][2] = {
    {0xCF928B9BBF6CB08Full, 0x00E275A0ABD218D4ull}, /* L=1, deg 119 */
    {0x7F18C258CFF6EFEFull, 0x0001E3F63D7659B3ull}, /* L=2, deg 112 */
    {0xB1030A5A1919808Bull, 0x000001BEF66C6C3Aull}, /* L=3, deg 104 */
    {0xDE17467FD3736AD9ull, 0x000000016AB89969ull}, /* L=4, deg 96 */
    {0x91DA50EC55715247ull, 0x0000000001630632ull}, /* L=5, deg 88 */
    {0x52AA6CC054468311ull, 0x0000000000002C93ull}, /* L=6, deg 77 */
    {0xF7FFFCE279F3A073ull, 0x00000000000000B3ull}, /* L=7, deg 71 */
    {0xA1AB815BC7EC8025ull, 0x0000000000000000ull}, /* L=8, deg 63 */
    {0x0002C98011D8B04Dull, 0x0000000000000000ull}, /* L=9, deg 49 */
    {0x0000058E24F9A4BBull, 0x0000000000000000ull}, /* L=10, deg 42 */
    {0x0000000CA76024D7ull, 0x0000000000000000ull}, /* L=11, deg 35 */
    {0x000000001C9C26B9ull, 0x0000000000000000ull}, /* L=12, deg 28 */
    {0x000000000026D9E3ull, 0x0000000000000000ull}, /* L=13, deg 21 */
    {0x0000000000004377ull, 0x0000000000000000ull}, /* L=14, deg 14 */
    {0x0000000000000089ull, 0x0000000000000000ull}, /* L=15, deg 7 */
};

/* ---- 128-bit polynomials over GF(2) as {lo, hi} ---- */
static int pbit(const uint64_t p[2], int i) { return (int)((p[i >> 6] >> (i & 63)) & 1u); }

static void pxor_shift(uint64_t acc[2], const uint64_t p[2], int s) /* acc ^= p << s (bits beyond 127 dropped) */
{
    for (int i = 127 - s; i >= 0; --i)
        if (pbit(p, i)) acc[(i + s) >> 6] ^= 1ull << ((i + s) & 63);
}

void br_e0_key_reduce(const uint8_t k_enc[16], int len_octets, uint8_t k_session[16])
{
    if (len_octets >= 16 || len_octets < 1) {
        memcpy(k_session, k_enc, 16);
        return;
    }
    uint64_t k[2] = {0, 0};
    for (int i = 0; i < 16; ++i) k[i >> 3] |= (uint64_t)k_enc[i] << (8 * (i & 7));
    const int d = 8 * len_octets;
    const uint64_t* g1 = kG1[len_octets - 1];
    for (int i = 127; i >= d; --i) {
        if (!pbit(k, i)) continue;
        k[i >> 6] ^= 1ull << (i & 63); /* the implicit x^d term */
        pxor_shift(k, g1, i - d);
    }
    uint64_t out[2] = {0, 0};
    for (int j = 0; j < d; ++j)
        if (pbit(k, j)) pxor_shift(out, kG2[len_octets - 1], j);
    for (int i = 0; i < 16; ++i) k_session[i] = (uint8_t)(out[i >> 3] >> (8 * (i & 7)));
}

/* ---- the key stream generator ---- */
static const int kLen[4] = {25, 31, 33, 39};
static const uint8_t kTaps[4][4] = {{25, 20, 12, 8}, {31, 24, 16, 12}, {33, 28, 24, 4}, {39, 36, 28, 4}};
/* Output taps: positions 24, 24, 32, 32 counted from the far end (= bits 23, 23, 31, 31 from the input end). */
static const uint8_t kOut[4] = {23, 23, 31, 31};

static int feedback(int i, uint64_t s)
{
    int v = 0;
    for (int k = 0; k < 4; ++k) v ^= (int)((s >> (kTaps[i][k] - 1)) & 1u);
    return v;
}

/* T2: (x1, x0) -> (x0, x1 ^ x0); T1 = identity. */
static uint8_t t2(uint8_t x) { return (uint8_t)(((x & 1u) << 1) | (((x >> 1) ^ x) & 1u)); }

/* One output symbol from the current state, then update the blend registers (summation combiner). */
static int combine(br_e0_t* e)
{
    int y = 0, z = 0;
    for (int i = 0; i < 4; ++i) {
        const int x = (int)((e->r[i] >> kOut[i]) & 1u);
        y += x;
        z ^= x;
    }
    z ^= e->c & 1;
    const uint8_t s = (uint8_t)((y + e->c) >> 1);
    const uint8_t next = (uint8_t)((s ^ e->c ^ t2(e->c1)) & 3u);
    e->c2 = e->c1;
    e->c1 = e->c;
    e->c = next;
    return z;
}

static void clock_lfsr(br_e0_t* e, int i, int in, int closed)
{
    const uint64_t mask = (1ull << kLen[i]) - 1;
    const int nb = in ^ (closed ? feedback(i, e->r[i]) : 0);
    e->r[i] = ((e->r[i] << 1) | (uint64_t)nb) & mask;
}

/* Input layout (Core Vol 2 Part H Figure 4.5; recovered from and verified against the Part G §1.1 traces):
 *   LFSR1: CL24, K[0], K[4], K[8], K[12], CL[1], ADDR[2]
 *   LFSR2: 1, 0, 0, CL0..3, K[1], K[5], K[9], K[13], ADDR[0], ADDR[3]
 *   LFSR3: CL25, K[2], K[6], K[10], K[14], CL[2], ADDR[4]
 *   LFSR4: 1, 1, 1, CL4..7, K[3], K[7], K[11], K[15], ADDR[1], ADDR[5]
 * listed in the order they enter, bytes LSB first. CL = CLK26..1 (CL0 = CLK1). */
static size_t build_input(int i, const uint8_t k[16], const uint8_t a[6], uint32_t cl, uint8_t out[8])
{
    memset(out, 0, 8);
    size_t n = 0;
#define BITS(v, cnt) (br_bits_write(out, n, (uint64_t)(v), (cnt)), n += (cnt))
    const uint8_t cl0 = (uint8_t)cl, cl1 = (uint8_t)(cl >> 8), cl2 = (uint8_t)(cl >> 16);
    switch (i) {
    case 0: BITS((cl >> 24) & 1u, 1); BITS(k[0], 8); BITS(k[4], 8); BITS(k[8], 8); BITS(k[12], 8); BITS(cl1, 8); BITS(a[2], 8); break;
    case 1: BITS(1, 1); BITS(0, 2); BITS(cl0 & 0xFu, 4); BITS(k[1], 8); BITS(k[5], 8); BITS(k[9], 8); BITS(k[13], 8); BITS(a[0], 8); BITS(a[3], 8); break;
    case 2: BITS((cl >> 25) & 1u, 1); BITS(k[2], 8); BITS(k[6], 8); BITS(k[10], 8); BITS(k[14], 8); BITS(cl2, 8); BITS(a[4], 8); break;
    default: BITS(7, 3); BITS(cl0 >> 4, 4); BITS(k[3], 8); BITS(k[7], 8); BITS(k[11], 8); BITS(k[15], 8); BITS(a[1], 8); BITS(a[5], 8); break;
    }
#undef BITS
    return n;
}

void br_e0_init(br_e0_t* e, const uint8_t k_session[16], const uint8_t bd_addr[6], uint32_t clk)
{
    const uint32_t cl = (clk >> 1) & 0x3FFFFFFu;
    uint8_t in[4][8];
    size_t len[4];
    for (int i = 0; i < 4; ++i) len[i] = build_input(i, k_session, bd_addr, cl, in[i]);
    memset(e, 0, sizeof *e);

    uint8_t z[16];
    memset(z, 0, sizeof z);
    for (int t = 1; t <= 239; ++t) {
        for (int i = 0; i < 4; ++i) {
            const int bit = (size_t)(t - 1) < len[i] ? br_bit_get(in[i], (size_t)(t - 1)) : 0;
            clock_lfsr(e, i, bit, t > kLen[i]);
        }
        if (t == 39) e->c = e->c1 = 0;
        if (t >= 39) {
            const int out = combine(e);
            if (t >= 112) br_bit_put(z, (size_t)(t - 112), out); /* the last 128 of the 200 symbols (t = 40..239) */
        }
    }
    /* Parallel load (Figure 4.6), blend registers kept. */
    e->r[0] = z[0] | (uint64_t)z[4] << 8 | (uint64_t)z[8] << 16 | (uint64_t)(z[12] & 1u) << 24;
    e->r[1] = z[1] | (uint64_t)z[5] << 8 | (uint64_t)z[9] << 16 | (uint64_t)(z[12] >> 1) << 24;
    e->r[2] = z[2] | (uint64_t)z[6] << 8 | (uint64_t)z[10] << 16 | (uint64_t)z[13] << 24 | (uint64_t)(z[15] & 1u) << 32;
    e->r[3] = z[3] | (uint64_t)z[7] << 8 | (uint64_t)z[11] << 16 | (uint64_t)z[14] << 24 | (uint64_t)(z[15] >> 1) << 32;
    e->fresh = 1;
}

/* The parallel load takes the place of clock t = 239's LFSR state: the blend registers step back one clock, so the
 * first keystream symbol uses c_239 and recomputes c_240 from the loaded registers (Part G §1.1, rows 239/240 of
 * all four sets). Every later symbol clocks normally. */
int br_e0_bit(br_e0_t* e)
{
    if (e->fresh) {
        e->c = e->c1;
        e->c1 = e->c2;
        e->fresh = 0;
    }
    const int z = combine(e);
    for (int i = 0; i < 4; ++i) clock_lfsr(e, i, 0, 1);
    return z;
}

void br_e0_apply(br_e0_t* e, uint8_t* buf, size_t pos, size_t n)
{
    for (size_t i = 0; i < n; ++i)
        if (br_e0_bit(e)) br_bit_put(buf, pos + i, !br_bit_get(buf, pos + i));
}
