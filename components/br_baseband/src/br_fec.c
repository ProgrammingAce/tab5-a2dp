#include "br/br_fec.h"

#include "br/br_bits.h"

void br_fec13_encode(const uint8_t* src, size_t src_pos, size_t n, uint8_t* dst, size_t dst_pos)
{
    for (size_t i = 0; i < n; ++i) {
        const int b = br_bit_get(src, src_pos + i);
        br_bit_put(dst, dst_pos + 3 * i, b);
        br_bit_put(dst, dst_pos + 3 * i + 1, b);
        br_bit_put(dst, dst_pos + 3 * i + 2, b);
    }
}

size_t br_fec13_decode(const uint8_t* src, size_t src_pos, size_t n, uint8_t* dst, size_t dst_pos)
{
    size_t disagree = 0;
    for (size_t i = 0; i < n; ++i) {
        const int a = br_bit_get(src, src_pos + 3 * i);
        const int b = br_bit_get(src, src_pos + 3 * i + 1);
        const int c = br_bit_get(src, src_pos + 3 * i + 2);
        br_bit_put(dst, dst_pos + i, (a & b) | (b & c) | (a & c));
        if (a != b || b != c) ++disagree;
    }
    return disagree;
}

/* g(D) = (D+1)(D^4+D+1) = D^5+D^4+D^2+1. Register position i = bit i; parity sent highest position first.
 * Cross-checked against libbtbb's generator matrix for all 1024 inputs (A2DP_PROGRESS.md). */
uint16_t br_fec23_block(uint16_t data10)
{
    uint32_t reg = 0;
    for (int i = 0; i < 10; ++i) {
        const uint32_t fb = ((data10 >> i) ^ (reg >> 4)) & 1u;
        reg = (reg << 1) & 0x1Fu;
        if (fb) reg ^= 0x15u; /* positions 0,2,4 */
    }
    return (uint16_t)((data10 & 0x3FFu) | (br_reverse_bits(reg, 5) << 10));
}

size_t br_fec23_encode(const uint8_t* src, size_t src_pos, size_t n, uint8_t* dst, size_t dst_pos)
{
    size_t out = 0;
    for (size_t i = 0; i < n; i += 10) {
        uint16_t d = 0;
        for (size_t k = 0; k < 10 && i + k < n; ++k) d |= (uint16_t)(br_bit_get(src, src_pos + i + k) << k);
        br_bits_write(dst, dst_pos + out, br_fec23_block(d), 15);
        out += 15;
    }
    return out;
}

/* Syndrome -> error position (0..14), built on first use. 0xFF = no single-bit error matches. */
static uint8_t syndrome_pos[32];
static int syndrome_ready;

static uint16_t syndrome_of(uint16_t cw) { return (uint16_t)((br_fec23_block(cw & 0x3FFu) ^ cw) >> 10); }

static void build_syndromes(void)
{
    for (int i = 0; i < 32; ++i) syndrome_pos[i] = 0xFF;
    for (int e = 0; e < 15; ++e) syndrome_pos[syndrome_of((uint16_t)(1u << e))] = (uint8_t)e;
    syndrome_ready = 1;
}

int br_fec23_decode(const uint8_t* src, size_t src_pos, size_t n, uint8_t* dst, size_t dst_pos, size_t* corrected)
{
    if (!syndrome_ready) build_syndromes();
    size_t fixes = 0;
    int ok = 0;
    for (size_t i = 0, in = 0; i < n; i += 10, in += 15) {
        uint16_t cw = (uint16_t)br_bits_read(src, src_pos + in, 15);
        const uint16_t s = syndrome_of(cw);
        if (s) {
            if (syndrome_pos[s] == 0xFF) ok = -1;
            else {
                cw ^= (uint16_t)(1u << syndrome_pos[s]);
                ++fixes;
            }
        }
        for (size_t k = 0; k < 10 && i + k < n; ++k) br_bit_put(dst, dst_pos + i + k, (cw >> k) & 1u);
    }
    if (corrected) *corrected = fixes;
    return ok;
}
