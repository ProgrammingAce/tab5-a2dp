#pragma once
/* Forward error correction. Core Vol 2 Part B §7.4 (1/3 repetition) and §7.5 ((15,10) shortened Hamming). */
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Rate 1/3: each input bit sent three times. Encodes `n` bits from src@src_pos to dst@dst_pos (3n bits). */
void br_fec13_encode(const uint8_t* src, size_t src_pos, size_t n, uint8_t* dst, size_t dst_pos);
/* Majority decode of 3n bits into n bits. Returns the number of bit triples that were not unanimous. */
size_t br_fec13_decode(const uint8_t* src, size_t src_pos, size_t n, uint8_t* dst, size_t dst_pos);

/* Rate 2/3 on one 10-bit block: returns the 15-bit codeword (data bits 0..9, parity bits 10..14 in transmit order). */
uint16_t br_fec23_block(uint16_t data10);
/* Encodes `n` data bits (padded with zeros to a multiple of 10) to 15/10 as many bits. Returns bits written. */
size_t br_fec23_encode(const uint8_t* src, size_t src_pos, size_t n, uint8_t* dst, size_t dst_pos);
/* Decodes enough 15-bit blocks to produce `n` data bits, correcting one error per block.
 * Returns 0 on success, -1 if a block had an uncorrectable error. `corrected` (may be NULL) counts fixes. */
int br_fec23_decode(const uint8_t* src, size_t src_pos, size_t n, uint8_t* dst, size_t dst_pos, size_t* corrected);
/* Number of coded bits for n data bits. */
static inline size_t br_fec23_coded_len(size_t n) { return (n + 9) / 10 * 15; }

#ifdef __cplusplus
}
#endif
