#pragma once
/* Packed LSB-first bit buffers: bit i lives in buf[i >> 3], bit (i & 7). Bit 0 = first bit on air. */
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

static inline int br_bit_get(const uint8_t* buf, size_t i) { return (buf[i >> 3] >> (i & 7)) & 1; }

static inline void br_bit_put(uint8_t* buf, size_t i, int v)
{
    if (v) buf[i >> 3] |= (uint8_t)(1u << (i & 7));
    else buf[i >> 3] &= (uint8_t)~(1u << (i & 7));
}

/* Writes the low `n` bits of `value` (bit 0 first) at bit position `pos`. n <= 64. */
void br_bits_write(uint8_t* buf, size_t pos, uint64_t value, unsigned n);
/* Reads `n` bits starting at `pos`; the first one read becomes bit 0 of the result. n <= 64. */
uint64_t br_bits_read(const uint8_t* buf, size_t pos, unsigned n);
/* Copies `n` bits from src (starting at src_pos) to dst (starting at dst_pos). */
void br_bits_copy(uint8_t* dst, size_t dst_pos, const uint8_t* src, size_t src_pos, size_t n);
int br_popcount64(uint64_t v);
/* Reverses the low `n` bits of v. */
uint32_t br_reverse_bits(uint32_t v, unsigned n);

#ifdef __cplusplus
}
#endif
