#include "br/br_fast.h"

#include <string.h>

#include "br/br_bits.h"
#include "br/br_crc.h"
#include "br/br_fec.h"
#include "br/br_whiten.h"

/* ---- fast E0 keystream -------------------------------------------------------------------------------------------
 * Same generator as br_e0.c (see the comments there for the spec layout). Each LFSR advances up to 4 clocks per step:
 * the lowest feedback tap is at register position 3, so after j <= 3 clocks position p still holds the old bit p - j
 * and all four feedback bits of the block come from the old register. The summation combiner is a 256-entry table. */
static const int kLen[4] = {25, 31, 33, 39};
static const uint8_t kTap[4][4] = {{24, 19, 11, 7}, {30, 23, 15, 11}, {32, 27, 23, 3}, {38, 35, 27, 3}};
static const uint8_t kOut[4] = {23, 23, 31, 31};

static uint8_t s_comb[256]; /* index x(4) | c << 4 | c1 << 6 -> z | next_c << 1 */
static int s_comb_ready;

static void comb_init(void)
{
    for (unsigned i = 0; i < 256; ++i) {
        const unsigned x = i & 15u, c = (i >> 4) & 3u, c1 = (i >> 6) & 3u;
        const unsigned y = (x & 1u) + ((x >> 1) & 1u) + ((x >> 2) & 1u) + ((x >> 3) & 1u);
        const unsigned z = (((x ^ (x >> 1) ^ (x >> 2) ^ (x >> 3)) & 1u) ^ (c & 1u));
        const unsigned s = (y + c) >> 1;
        const unsigned t2 = ((c1 & 1u) << 1) | (((c1 >> 1) ^ c1) & 1u);
        s_comb[i] = (uint8_t)(z | (((s ^ c ^ t2) & 3u) << 1));
    }
    s_comb_ready = 1;
}

typedef struct {
    uint64_t r[4];
    unsigned c, c1, c2;
} fe0_t;

/* k clocks (1..4) of LFSR i with input bits `in` (bit k-1-j = input of clock j) and closed-loop flags `cl` (same
 * layout). */
static inline uint64_t lfsr_step(uint64_t r, int i, unsigned k, unsigned in, unsigned cl)
{
    const unsigned sh = k - 1u;
    const uint64_t fb = (r >> (kTap[i][0] - sh)) ^ (r >> (kTap[i][1] - sh)) ^ (r >> (kTap[i][2] - sh)) ^
                        (r >> (kTap[i][3] - sh));
    const unsigned m = (1u << k) - 1u;
    const unsigned nb = (in ^ ((unsigned)fb & cl)) & m;
    return ((r << k) | nb) & ((1ull << kLen[i]) - 1u);
}

static inline unsigned combine(fe0_t* e, unsigned x)
{
    const unsigned v = s_comb[x | (e->c << 4) | (e->c1 << 6)];
    e->c2 = e->c1;
    e->c1 = e->c;
    e->c = v >> 1;
    return v & 1u;
}

static inline uint64_t rev64(uint64_t v)
{
    v = ((v >> 1) & 0x5555555555555555ull) | ((v & 0x5555555555555555ull) << 1);
    v = ((v >> 2) & 0x3333333333333333ull) | ((v & 0x3333333333333333ull) << 2);
    v = ((v >> 4) & 0x0F0F0F0F0F0F0F0Full) | ((v & 0x0F0F0F0F0F0F0F0Full) << 4);
    v = ((v >> 8) & 0x00FF00FF00FF00FFull) | ((v & 0x00FF00FF00FF00FFull) << 8);
    v = ((v >> 16) & 0x0000FFFF0000FFFFull) | ((v & 0x0000FFFF0000FFFFull) << 16);
    return (v >> 32) | (v << 32);
}

/* 5-bit output windows: bit (4 - d) of window i = r_i[out_i - d], d = 0..4; packed so that x(d) is one lookup. */
static inline uint32_t xwin(const uint64_t r[4])
{
    return (uint32_t)((r[0] >> (kOut[0] - 4)) & 0x1Fu) | (uint32_t)(((r[1] >> (kOut[1] - 4)) & 0x1Fu) << 5) |
           (uint32_t)(((r[2] >> (kOut[2] - 4)) & 0x1Fu) << 10) | (uint32_t)(((r[3] >> (kOut[3] - 4)) & 0x1Fu) << 15);
}
static inline unsigned xat(uint32_t w, unsigned d)
{
    const unsigned s = 4u - d;
    return ((w >> s) & 1u) | (((w >> (5u + s)) & 1u) << 1) | (((w >> (10u + s)) & 1u) << 2) | (((w >> (15u + s)) & 1u) << 3);
}

static void fe0_init(fe0_t* e, const uint8_t k[16], const uint8_t a[6], uint32_t clk)
{
    if (!s_comb_ready) comb_init();
    const uint32_t cl = (clk >> 1) & 0x3FFFFFFu;
    const uint32_t cl0 = cl & 0xFFu, cl1 = (cl >> 8) & 0xFFu, cl2 = (cl >> 16) & 0xFFu;
    uint64_t in[4];
    unsigned len[4];
#define PUT(i, v, cnt) (in[i] |= ((uint64_t)(v) & ((1ull << (cnt)) - 1u)) << len[i], len[i] += (cnt))
    for (int i = 0; i < 4; ++i) { in[i] = 0; len[i] = 0; }
    PUT(0, (cl >> 24) & 1u, 1); PUT(0, k[0], 8); PUT(0, k[4], 8); PUT(0, k[8], 8); PUT(0, k[12], 8); PUT(0, cl1, 8); PUT(0, a[2], 8);
    PUT(1, 1, 1); PUT(1, 0, 2); PUT(1, cl0 & 0xFu, 4); PUT(1, k[1], 8); PUT(1, k[5], 8); PUT(1, k[9], 8); PUT(1, k[13], 8); PUT(1, a[0], 8); PUT(1, a[3], 8);
    PUT(2, (cl >> 25) & 1u, 1); PUT(2, k[2], 8); PUT(2, k[6], 8); PUT(2, k[10], 8); PUT(2, k[14], 8); PUT(2, cl2, 8); PUT(2, a[4], 8);
    PUT(3, 7, 3); PUT(3, cl0 >> 4, 4); PUT(3, k[3], 8); PUT(3, k[7], 8); PUT(3, k[11], 8); PUT(3, k[15], 8); PUT(3, a[1], 8); PUT(3, a[5], 8);
#undef PUT
    /* inR bit 63 = input of clock 1: the 4 inputs of clocks t0..t0+3, first clock highest, are one shift away */
    uint64_t inr[4];
    for (int i = 0; i < 4; ++i) inr[i] = rev64(in[i]);
    memset(e, 0, sizeof *e);
    uint8_t z[16];
    memset(z, 0, sizeof z);
    unsigned t0 = 1;
    /* clocks 1..56: inputs and open/closed loops (all inputs end by clock 55, all loops closed after clock 39) */
    for (; t0 <= 53; t0 += 4) {
        const uint64_t old[4] = {e->r[0], e->r[1], e->r[2], e->r[3]};
        const uint32_t w = xwin(old);
        for (int i = 0; i < 4; ++i) {
            const unsigned ib = (unsigned)(inr[i] >> (60u - (t0 - 1u))) & 0xFu;
            const int L = kLen[i];
            const unsigned cb = (int)t0 > L ? 0xFu : ((int)t0 + 3 <= L ? 0u : (1u << (t0 + 3u - (unsigned)L)) - 1u);
            e->r[i] = lfsr_step(old[i], i, 4, ib, cb);
        }
        for (unsigned j = 0; j < 4; ++j) {
            const unsigned t = t0 + j;
            if (t == 39) e->c = e->c1 = 0;
            if (t >= 39) (void)combine(e, xat(w, j + 1u));
        }
    }
    /* clocks 57..239: closed loops, no input */
    for (; t0 <= 239; t0 += 4) {
        const unsigned k4 = t0 + 3 <= 239 ? 4u : 240u - t0;
        const uint32_t w = xwin(e->r);
        for (int i = 0; i < 4; ++i) e->r[i] = lfsr_step(e->r[i], i, k4, 0, 0xFu);
        for (unsigned j = 0; j < k4; ++j) {
            const unsigned t = t0 + j;
            const unsigned out = combine(e, xat(w, j + 1u));
            if (t >= 112) z[(t - 112) >> 3] |= (uint8_t)(out << ((t - 112) & 7u));
        }
    }
    e->r[0] = z[0] | (uint64_t)z[4] << 8 | (uint64_t)z[8] << 16 | (uint64_t)(z[12] & 1u) << 24;
    e->r[1] = z[1] | (uint64_t)z[5] << 8 | (uint64_t)z[9] << 16 | (uint64_t)(z[12] >> 1) << 24;
    e->r[2] = z[2] | (uint64_t)z[6] << 8 | (uint64_t)z[10] << 16 | (uint64_t)z[13] << 24 | (uint64_t)(z[15] & 1u) << 32;
    e->r[3] = z[3] | (uint64_t)z[7] << 8 | (uint64_t)z[11] << 16 | (uint64_t)z[14] << 24 | (uint64_t)(z[15] >> 1) << 32;
    /* the parallel load replaces clock 239's state: blend registers step back once (br_e0_bit's `fresh`) */
    e->c = e->c1;
    e->c1 = e->c2;
}

void br_e0_keystream(const uint8_t k_session[16], const uint8_t bd_addr[6], uint32_t clk, uint8_t* out, size_t nbits)
{
    fe0_t e;
    fe0_init(&e, k_session, bd_addr, clk);
    memset(out, 0, (nbits + 7) / 8);
    for (size_t b = 0; b < nbits; b += 4) {
        const unsigned k4 = nbits - b >= 4 ? 4u : (unsigned)(nbits - b);
        const uint32_t w = xwin(e.r);
        unsigned nib = 0;
        for (unsigned j = 0; j < k4; ++j) nib |= combine(&e, xat(w, j)) << j; /* before clock j: old bit o - j */
        out[b >> 3] |= (uint8_t)(nib << (b & 7u));
        for (int i = 0; i < 4; ++i) e.r[i] = lfsr_step(e.r[i], i, k4, 0, 0xFu);
    }
}

/* ---- slot masks, plain payloads, headers ------------------------------------------------------------------------- */
void br_fast_mask(uint32_t clk, const uint8_t* k_session, const uint8_t* bd_addr, uint8_t mask[BR_FAST_PAYLOAD_BYTES])
{
    br_whiten_t w;
    br_whiten_init(&w, (uint8_t)((clk >> 1) & 63u));
    for (int i = 0; i < 18; ++i) (void)br_whiten_next(&w);
    memset(mask, 0, BR_FAST_PAYLOAD_BYTES);
    for (unsigned i = 0; i < BR_FAST_PAYLOAD_BITS; ++i) mask[i >> 3] |= (uint8_t)(br_whiten_next(&w) << (i & 7u));
    if (k_session) {
        uint8_t ks[BR_FAST_PAYLOAD_BYTES];
        br_e0_keystream(k_session, bd_addr, clk, ks, BR_FAST_PAYLOAD_BITS);
        for (unsigned i = 0; i < BR_FAST_PAYLOAD_BYTES; ++i) mask[i] ^= ks[i];
    }
}

size_t br_fast_plain(uint8_t llid, uint8_t pflow, const uint8_t* data, size_t len, uint8_t uap,
                     uint8_t plain[BR_FAST_PAYLOAD_BYTES])
{
    if (len > 27) len = 27;
    memset(plain, 0, BR_FAST_PAYLOAD_BYTES);
    plain[0] = (uint8_t)((llid & 3u) | ((pflow & 1u) << 2) | ((unsigned)len << 3));
    memcpy(plain + 1, data, len);
    const size_t n = 8 * (1 + len);
    const uint16_t crc = br_crc16(plain, 0, n, uap);
    plain[1 + len] = (uint8_t)crc;
    plain[2 + len] = (uint8_t)(crc >> 8);
    return n + 16;
}

uint64_t br_fast_header(const br_header_t* h, uint8_t uap, uint8_t clk6)
{
    uint8_t buf[8] = {0};
    br_whiten_t w;
    br_whiten_init(&w, clk6);
    br_header_encode(h, uap, &w, buf, 0);
    return br_bits_read(buf, 0, 54);
}

uint32_t br_fast_header_whitening(uint8_t clk6)
{
    br_whiten_t w;
    br_whiten_init(&w, clk6);
    uint32_t v = 0;
    for (unsigned i = 0; i < 18; ++i) v |= (uint32_t)br_whiten_next(&w) << i;
    return v;
}

void br_fast_fec23_table(uint16_t table[1024])
{
    for (unsigned d = 0; d < 1024; ++d) table[d] = br_fec23_block((uint16_t)d);
}

/* OR n (<= 25) bits of v into out at bit p. */
static BR_FAST_ATTR inline void or_bits(uint8_t* out, size_t p, uint32_t v, unsigned n)
{
    const uint32_t w = (v & ((1u << n) - 1u)) << (p & 7u);
    uint8_t* o = out + (p >> 3);
    o[0] |= (uint8_t)w;
    if ((p & 7u) + n > 8) o[1] |= (uint8_t)(w >> 8);
    if ((p & 7u) + n > 16) o[2] |= (uint8_t)(w >> 16);
    if ((p & 7u) + n > 24) o[3] |= (uint8_t)(w >> 24);
}

size_t br_fast_payload(uint8_t type, const uint8_t* plain, size_t nbits, const uint8_t* mask,
                       const uint16_t* fec23_table, uint8_t* out, size_t pos)
{
    uint8_t x[BR_FAST_PAYLOAD_BYTES + 2];
    const size_t nb = (nbits + 7) / 8;
    for (size_t i = 0; i < nb; ++i) x[i] = plain[i] ^ mask[i];
    if (nbits & 7u) x[nb - 1] &= (uint8_t)((1u << (nbits & 7u)) - 1u);
    x[nb] = x[nb + 1] = 0;
    if (type != 0x3 /* DM1 */) {
        for (size_t i = 0; i + 8 <= nbits; i += 8) or_bits(out, pos + i, x[i >> 3], 8);
        if (nbits & 7u) or_bits(out, pos + (nbits & ~(size_t)7u), x[nb - 1], (unsigned)(nbits & 7u));
        return nbits;
    }
    size_t o = pos;
    for (size_t i = 0; i < nbits; i += 10) {
        const uint32_t w = (uint32_t)x[i >> 3] | ((uint32_t)x[(i >> 3) + 1] << 8) | ((uint32_t)x[(i >> 3) + 2] << 16);
        or_bits(out, o, fec23_table[(w >> (i & 7u)) & 0x3FFu], 15);
        o += 15;
    }
    return o - pos;
}
