#include "br/br_access_code.h"

#include "br/br_bits.h"

/* PN overlay p0..p63, bit i = p_i. Core Vol 2 Part B §6.3.3.1. */
static const uint64_t kPn = 0x83848D96BBCC54FCull;
/* BCH(64,30) generator g(D), octal 260534236651 (degree 34), coefficient of D^i in bit i. Same section. */
static const uint64_t kBchGen = 0260534236651ull; /* octal */

uint64_t br_sync_word(uint32_t lap)
{
    /* x0..x29: LAP a0..a23 then the 6-bit Barker sequence chosen by a23. */
    uint64_t x = lap & 0xFFFFFFu;
    const uint64_t barker = ((lap >> 23) & 1u) ? 0x13u /* 110010 on air */ : 0x2Cu /* 001101 on air */;
    x |= barker << 24;
    /* x~ = x XOR p34..p63 */
    const uint64_t xt = x ^ (kPn >> 34);
    /* Parity c0..c33 = x~(D) * D^34 mod g(D) */
    uint64_t poly = xt << 34;
    for (int d = 63; d >= 34; --d)
        if ((poly >> d) & 1u) poly ^= kBchGen << (d - 34);
    const uint64_t parity = poly & ((1ull << 34) - 1);
    return (parity | (xt << 34)) ^ kPn;
}

size_t br_access_code_bits(uint32_t lap, int with_trailer, uint8_t* buf)
{
    const uint64_t sw = br_sync_word(lap);
    /* Preamble 1010 if s0 = 1, else 0101 (transmission order). Trailer 1010 if s63 = 0, else 0101. §6.3.1/§6.3.4 */
    br_bits_write(buf, 0, (sw & 1u) ? 0x5u /* bits 1,0,1,0 */ : 0xAu /* 0,1,0,1 */, 4);
    br_bits_write(buf, 4, sw, 64);
    if (!with_trailer) return 68;
    br_bits_write(buf, 68, ((sw >> 63) & 1u) ? 0xAu : 0x5u, 4);
    return 72;
}
