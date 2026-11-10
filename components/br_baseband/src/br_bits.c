#include "br/br_bits.h"

void br_bits_write(uint8_t* buf, size_t pos, uint64_t value, unsigned n)
{
    for (unsigned i = 0; i < n; ++i) br_bit_put(buf, pos + i, (int)((value >> i) & 1u));
}

uint64_t br_bits_read(const uint8_t* buf, size_t pos, unsigned n)
{
    uint64_t v = 0;
    for (unsigned i = 0; i < n; ++i) v |= (uint64_t)br_bit_get(buf, pos + i) << i;
    return v;
}

void br_bits_copy(uint8_t* dst, size_t dst_pos, const uint8_t* src, size_t src_pos, size_t n)
{
    for (size_t i = 0; i < n; ++i) br_bit_put(dst, dst_pos + i, br_bit_get(src, src_pos + i));
}

int br_popcount64(uint64_t v)
{
    int c = 0;
    while (v) {
        v &= v - 1;
        ++c;
    }
    return c;
}

uint32_t br_reverse_bits(uint32_t v, unsigned n)
{
    uint32_t r = 0;
    for (unsigned i = 0; i < n; ++i) r |= ((v >> i) & 1u) << (n - 1 - i);
    return r;
}
